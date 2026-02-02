package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// =====================
// Config via CLI flags
// =====================

var (
	baseURL           = flag.String("url", "https://hashcash-pow-faucet.dynv6.net/api", "Base URL of the faucet API")
	privateKey        = flag.String("key", "", "Private key (from the web faucet)")
	workers           = flag.Int("workers", 4, "Number of PoW worker goroutines (0 = auto-detect CPU cores)")
	stopAtCap         = flag.Bool("stop-at-cap", true, "Stop when daily earn cap is reached")
	extremeMode       = flag.Bool("extreme", false, "Enable HashCash Extreme mode (no cooldown, higher difficulty, separate daily cap)")
	showProgress      = flag.Bool("progress", true, "Show live PoW progress (hashrate/ETA) while searching")
	progressIntervalS = flag.Int("progress-interval", 2, "Progress update interval in seconds")
	client            = &http.Client{Timeout: 30 * time.Second}
)

// =====================
// Types (API structs)
// =====================

type MeResponse struct {
	AccountID     string `json:"account_id"`
	Credits       int    `json:"credits"`
	EarnedToday   int    `json:"earned_today"`
	DailyEarnCap  int    `json:"daily_earn_cap"`
	CooldownUntil int64  `json:"cooldown_until"`
	ServerTime    int64  `json:"server_time"`
}

type ChallengeRequest struct {
	Action string `json:"action"`
}

type ChallengeResponse struct {
	Stamp string `json:"stamp"`
	Bits  int    `json:"bits"`
	Sig   string `json:"sig"`
}

type SubmitRequest struct {
	Stamp string `json:"stamp"`
	Sig   string `json:"sig"`
	Nonce string `json:"nonce"`
}

type SubmitResponse struct {
	OK            bool   `json:"ok"`
	Credits       int    `json:"credits"`
	NextSeq       int    `json:"next_seq"`
	CooldownUntil int64  `json:"cooldown_until"`
	Message       string `json:"message,omitempty"`
}

// =====================
// HTTP helpers
// =====================

func apiGet(path string, into interface{}) error {
	req, err := http.NewRequest("GET", *baseURL+path, nil)
	if err != nil {
		return err
	}
	if *privateKey != "" {
		req.Header.Set("Authorization", "Bearer "+*privateKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s failed: %s - %s", path, resp.Status, string(body))
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			return fmt.Errorf("unmarshal %s: %w", path, err)
		}
	}
	return nil
}

func apiPost(path string, payload interface{}, into interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", *baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if *privateKey != "" {
		req.Header.Set("Authorization", "Bearer "+*privateKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s failed: %s - %s", path, resp.Status, string(body))
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			return fmt.Errorf("unmarshal %s: %w", path, err)
		}
	}
	return nil
}

func cancelPow() {
	req, err := http.NewRequest("POST", *baseURL+"/cancel_pow", nil)
	if err != nil {
		fmt.Println("[!] cancel_pow: build request:", err)
		return
	}
	if *privateKey != "" {
		req.Header.Set("Authorization", "Bearer "+*privateKey)
	}

	// Use a short timeout for best-effort cleanup
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println("[!] cancel_pow:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("[!] cancel_pow failed:", resp.Status, "-", string(body))
		return
	}

	fmt.Println("[*] cancel_pow: ok (best-effort)")
}

// =====================
// PoW implementation
// =====================

func leadingZeroBits(b []byte) int {
	total := 0
	for _, v := range b {
		if v == 0 {
			total += 8
			continue
		}
		// bits.LeadingZeros8 returns 0–8 for the 8-bit value.
		total += bits.LeadingZeros8(uint8(v))
		break
	}
	return total
}

type powResult struct {
	Nonce   uint64
	Tries   uint64
	Elapsed time.Duration
	RateKHS float64
}

// Multi-worker PoW solver; workers search nonces i, i+N, i+2N, ...
func solvePow(stamp string, bits int, numWorkers int, showProg bool, progInterval time.Duration) powResult {
	if numWorkers < 1 {
		numWorkers = 1
	}
	done := make(chan struct{})
	resultCh := make(chan powResult, 1)

	start := time.Now()

	var totalTries uint64

	// Optional progress ticker
	if showProg {
		if progInterval <= 0 {
			progInterval = 2 * time.Second
		}
		t := time.NewTicker(progInterval)
		go func() {
			defer t.Stop()
			exp := expectedTries(bits)
			for {
				select {
				case <-done:
					return
				case <-t.C:
					tries := atomic.LoadUint64(&totalTries)
					elapsed := time.Since(start)
					rate := float64(tries) / elapsed.Seconds() / 1000.0
					eta := time.Duration(0)
					if rate > 0 {
						remaining := exp - float64(tries)
						if remaining < 0 {
							remaining = 0
						}
						eta = time.Duration(remaining/(rate*1000.0)) * time.Second
					}
					fmt.Printf("\r[*] PoW searching... tries=%d  rate=%.1f kH/s  ETA≈%s", tries, rate, fmtMMSS(eta))
				}
			}
		}()
	}

	for w := 0; w < numWorkers; w++ {
		go func(startNonce uint64) {
			// Prebuild the constant prefix "stamp|"
			prefix := append([]byte(stamp), '|')
			// Reusable buffer: prefix + up to ~20 digits of nonce
			buf := make([]byte, len(prefix), len(prefix)+24)
			copy(buf, prefix)

			var tries uint64
			nonce := startNonce
			step := uint64(numWorkers)

			for {
				select {
				case <-done:
					return
				default:
				}

				// Rebuild buffer: prefix + decimal nonce
				b := buf[:len(prefix)]
				b = strconv.AppendUint(b, nonce, 10)

				sum := sha256.Sum256(b)
				tries++

				// Flush to global counter in chunks to reduce atomic overhead
				if (tries & 0xFFF) == 0 {
					atomic.AddUint64(&totalTries, 0x1000)
				}

				if leadingZeroBits(sum[:]) >= bits {
					// Flush remainder (tries is local count; adjust by the last partial chunk)
					atomic.AddUint64(&totalTries, tries&0xFFF)
					elapsed := time.Since(start)
					triesGlobal := atomic.LoadUint64(&totalTries)
					rate := float64(triesGlobal) / elapsed.Seconds() / 1000.0
					res := powResult{
						Nonce:   nonce,
						Tries:   triesGlobal,
						Elapsed: elapsed,
						RateKHS: rate,
					}
					select {
					case resultCh <- res:
						close(done)
					default:
					}
					return
				}

				nonce += step
			}
		}(uint64(w))
	}

	// Take first result
	res := <-resultCh
	if showProg {
		// Clear the progress line
		fmt.Printf("\r")
	}
	return res
}

// =====================
// Small UI helpers
// =====================

func fmtMMSS(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d.Seconds())
	m := s / 60
	sec := s % 60
	return fmt.Sprintf("%dm %02ds", m, sec)
}

func expectedTries(bits int) float64 {
	// Expected number of trials for a random oracle is ~2^bits.
	// Use Ldexp to avoid invalid float shifts and to handle larger bit values safely.
	if bits <= 0 {
		return 1
	}
	return math.Ldexp(1.0, bits) // 1.0 * 2^bits
}

func sleepWithCountdown(totalSeconds int64) {
	if totalSeconds <= 0 {
		return
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for remaining := totalSeconds; remaining > 0; remaining-- {
		min := remaining / 60
		sec := remaining % 60
		fmt.Printf("\r[*] Cooldown active, waiting %dm %02ds...", min, sec)
		<-ticker.C
	}
	fmt.Printf("\r[*] Cooldown done.                      \n\n")
}

// =====================
// Mining logic
// =====================

func getAccountInfo() (*MeResponse, error) {
	var me MeResponse
	if err := apiGet("/me", &me); err != nil {
		return nil, err
	}
	return &me, nil
}

func requestChallenge(extreme bool) (*ChallengeResponse, error) {
	var (
		path   = "/challenge"
		action = "earn_credit"
	)
	if extreme {
		path = "/challenge_extreme"
		action = "earn_extreme"
	}

	var ch ChallengeResponse
	if err := apiPost(path, ChallengeRequest{Action: action}, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

func submitPow(stamp, sig string, nonce uint64) (*SubmitResponse, error) {
	var resp SubmitResponse
	payload := SubmitRequest{
		Stamp: stamp,
		Sig:   sig,
		Nonce: fmt.Sprintf("%d", nonce),
	}
	if err := apiPost("/submit_pow", payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func mineOneCredit(extreme bool) (*SubmitResponse, powResult, error) {
	ch, err := requestChallenge(extreme)
	if err != nil {
		return nil, powResult{}, err
	}

	modeLabel := "normal"
	if extreme {
		modeLabel = "EXTREME"
	}

	fmt.Printf("[+] Challenge (%s): bits=%d, stamp=%s...\n", modeLabel, ch.Bits, ch.Stamp[:32])

	interval := time.Duration(*progressIntervalS) * time.Second
	res := solvePow(ch.Stamp, ch.Bits, *workers, *showProgress, interval)
	khs := float64(res.Tries) / res.Elapsed.Seconds() / 1000.0
	fmt.Printf("[+] PoW solved (%s): nonce=%d, time=%.2fs, rate≈%.1f kH/s (%d workers)\n",
		modeLabel, res.Nonce, res.Elapsed.Seconds(), khs, *workers)

	sub, err := submitPow(ch.Stamp, ch.Sig, res.Nonce)
	if err != nil {
		return nil, res, err
	}
	return sub, res, nil
}

// =====================
// Main loop
// =====================

func main() {
	flag.Parse()

	// Auto-detect worker count if set to 0 or below
	if *workers <= 0 {
		*workers = runtime.NumCPU()
	}

	if *privateKey == "" {
		fmt.Println("ERROR: please provide -key with your private faucet key.")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("=== Hashcash PoW Faucet CLI Miner ===")
	fmt.Println("Base URL:", *baseURL)
	fmt.Println("Workers:", *workers)
	fmt.Println("Stop at daily cap:", *stopAtCap)
	fmt.Println("Live progress:", *showProgress, "(interval:", *progressIntervalS, "s)")
	if *extremeMode {
		fmt.Println("Mode: EXTREME (no cooldown, higher difficulty, separate daily cap)")
	} else {
		fmt.Println("Mode: normal")
	}
	fmt.Println("Press Ctrl+C to stop.\n")
	// Best-effort cleanup on Ctrl+C / SIGTERM: release the IP mining lock
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Caught Ctrl+C / SIGTERM -> releasing IP lock...")
		cancelPow()
		os.Exit(0)
	}()

	sessionStart := time.Now()
	lastKnownCredits := -1
	var sessionCreditsEarned int
	var sessionPowTries uint64
	var sessionPowTime time.Duration
	var sessionSolved int

	for {
		me, err := getAccountInfo()
		if err != nil {
			fmt.Println("[!] /me error:", err)
			time.Sleep(10 * time.Second)
			continue
		}

		fmt.Printf("Account: %s\n", me.AccountID)
		fmt.Printf("  Credits: %d\n", me.Credits)
		if *extremeMode {
			fmt.Printf("  Earned EXTREME today: %d\n", me.EarnedToday)
		} else {
			fmt.Printf("  Earned today: %d / %d\n", me.EarnedToday, me.DailyEarnCap)
		}

		if lastKnownCredits < 0 {
			lastKnownCredits = me.Credits
		}

		if !*extremeMode && *stopAtCap && me.DailyEarnCap > 0 && me.EarnedToday >= me.DailyEarnCap {
			fmt.Println("[*] Daily cap reached, stopping miner.")
			break
		}

		if !*extremeMode {
			now := me.ServerTime
			if me.CooldownUntil > now {
				wait := me.CooldownUntil - now + 2
				sleepWithCountdown(wait)
				continue
			}
		}

		if *extremeMode {
			fmt.Println("[*] Mining one EXTREME credit...")
		} else {
			fmt.Println("[*] Mining one credit...")
		}

		sub, powRes, err := mineOneCredit(*extremeMode)
		if err != nil {
			// If the server reports that the extreme daily cap has been reached, stop cleanly.
			if *extremeMode && strings.Contains(err.Error(), "extreme daily cap") {
				fmt.Println("[*] Extreme daily cap reached according to server, stopping miner.")
				break
			}
			fmt.Println("[!] Mining error:", err)
			time.Sleep(10 * time.Second)
			continue
		}

		// Session stats
		sessionSolved++
		sessionPowTries += powRes.Tries
		sessionPowTime += powRes.Elapsed

		delta := sub.Credits - lastKnownCredits
		if delta < 0 {
			delta = 0
		}
		sessionCreditsEarned += delta
		lastKnownCredits = sub.Credits

		sessionDur := time.Since(sessionStart)
		creditsPerHour := 0.0
		if sessionDur.Seconds() > 0 {
			creditsPerHour = float64(sessionCreditsEarned) / sessionDur.Hours()
		}
		avgKHS := 0.0
		if sessionPowTime.Seconds() > 0 {
			avgKHS = float64(sessionPowTries) / sessionPowTime.Seconds() / 1000.0
		}

		fmt.Printf("[+] Submit ok: credits=%d, next_seq=%d\n", sub.Credits, sub.NextSeq)
		fmt.Printf("    Session: +%d credits in %s (%.2f credits/hour), avg PoW rate≈%.1f kH/s, solves=%d\n\n",
			sessionCreditsEarned, fmtMMSS(sessionDur), creditsPerHour, avgKHS, sessionSolved)

		time.Sleep(2 * time.Second)
	}
}

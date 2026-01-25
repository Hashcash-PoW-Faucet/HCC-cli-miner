package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// =====================
// Config via CLI flags
// =====================

var (
	baseURL    = flag.String("url", "https://hashcash-pow-faucet.dynv6.net/api", "Base URL of the faucet API")
	privateKey = flag.String("key", "", "Private key (from the web faucet)")
	workers    = flag.Int("workers", 4, "Number of PoW worker goroutines")
	stopAtCap  = flag.Bool("stop-at-cap", true, "Stop when daily earn cap is reached")
	client     = &http.Client{Timeout: 30 * time.Second}
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
	bits := 0
	for _, by := range b {
		if by == 0 {
			bits += 8
		} else {
			for j := 7; j >= 0; j-- {
				if ((by >> uint(j)) & 1) == 0 {
					bits++
				} else {
					return bits
				}
			}
			return bits
		}
	}
	return bits
}

type powResult struct {
	Nonce   uint64
	Tries   uint64
	Elapsed time.Duration
}

// Multi-worker PoW solver; workers search nonces i, i+N, i+2N, ...
func solvePow(stamp string, bits int, numWorkers int) powResult {
	if numWorkers < 1 {
		numWorkers = 1
	}
	done := make(chan struct{})
	resultCh := make(chan powResult, 1)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		go func(startNonce uint64) {
			var tries uint64
			nonce := startNonce
			step := uint64(numWorkers)
			for {
				select {
				case <-done:
					return
				default:
				}
				msg := fmt.Sprintf("%s|%d", stamp, nonce)
				sum := sha256.Sum256([]byte(msg))
				if leadingZeroBits(sum[:]) >= bits {
					elapsed := time.Since(start)
					triesLocal := tries + 1
					res := powResult{
						Nonce:   nonce,
						Tries:   triesLocal,
						Elapsed: elapsed,
					}
					select {
					case resultCh <- res:
						close(done)
					default:
					}
					return
				}
				nonce += step
				tries++
			}
		}(uint64(w))
	}

	// Take first result
	res := <-resultCh
	// Approximate total tries as workerTries * numWorkers
	res.Tries = res.Tries * uint64(numWorkers)
	return res
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

func requestChallenge() (*ChallengeResponse, error) {
	var ch ChallengeResponse
	if err := apiPost("/challenge", ChallengeRequest{Action: "earn_credit"}, &ch); err != nil {
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

func mineOneCredit() (*SubmitResponse, error) {
	ch, err := requestChallenge()
	if err != nil {
		return nil, err
	}

	fmt.Printf("[+] Challenge: bits=%d, stamp=%s...\n", ch.Bits, ch.Stamp[:32])

	res := solvePow(ch.Stamp, ch.Bits, *workers)
	khs := float64(res.Tries) / res.Elapsed.Seconds() / 1000.0
	fmt.Printf("[+] PoW solved: nonce=%d, time=%.2fs, rate≈%.1f kH/s (%d workers)\n",
		res.Nonce, res.Elapsed.Seconds(), khs, *workers)

	sub, err := submitPow(ch.Stamp, ch.Sig, res.Nonce)
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// =====================
// Main loop
// =====================

func main() {
	flag.Parse()

	if *privateKey == "" {
		fmt.Println("ERROR: please provide -key with your private faucet key.")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("=== Hashcash PoW Faucet CLI Miner ===")
	fmt.Println("Base URL:", *baseURL)
	fmt.Println("Workers:", *workers)
	fmt.Println("Stop at daily cap:", *stopAtCap)
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

	for {
		me, err := getAccountInfo()
		if err != nil {
			fmt.Println("[!] /me error:", err)
			time.Sleep(10 * time.Second)
			continue
		}

		fmt.Printf("Account: %s\n", me.AccountID)
		fmt.Printf("  Credits: %d\n", me.Credits)
		fmt.Printf("  Earned today: %d / %d\n", me.EarnedToday, me.DailyEarnCap)

		if *stopAtCap && me.DailyEarnCap > 0 && me.EarnedToday >= me.DailyEarnCap {
			fmt.Println("[*] Daily cap reached, stopping miner.")
			break
		}

		now := me.ServerTime
		if me.CooldownUntil > now {
			wait := me.CooldownUntil - now + 2
			min := wait / 60
			sec := wait % 60
			fmt.Printf("[*] Cooldown active, waiting %dm %ds...\n\n", min, sec)
			time.Sleep(time.Duration(wait) * time.Second)
			continue
		}

		fmt.Println("[*] Mining one credit...")
		sub, err := mineOneCredit()
		if err != nil {
			fmt.Println("[!] Mining error:", err)
			time.Sleep(10 * time.Second)
			continue
		}
		fmt.Printf("[+] Submit ok: credits=%d, next_seq=%d\n\n", sub.Credits, sub.NextSeq)
		time.Sleep(2 * time.Second)
	}
}

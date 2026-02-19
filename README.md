# Hashcash Credits (HCC) CLI Miner

This is a simple command‑line miner for the experimental **Hashcash PoW Faucet**.  
It talks to the public HTTP API (`/me`, `/challenge`, `/challenge_extreme`, `/submit_pow`, `/cancel_pow`) and solves
Proof‑of‑Work challenges to claim credit points for a given faucet **private key**.

The miner is written in Go, uses only the standard library and supports
multi‑core CPUs via worker goroutines.

---

## Features

- Connects to the Hashcash Faucet HTTP API:
  - `/me` – account info
  - `/challenge` – normal mining challenge
  - `/challenge_extreme` – **Extreme Mode** challenge
  - `/submit_pow` – submit PoW solutions
  - `/cancel_pow` – best‑effort lock release on shutdown
- Uses your faucet *private key* (the random token from the web UI) as bearer token.
- **Multi‑threaded PoW** with configurable workers.
  - `-workers=0` ⇒ auto‑detects `runtime.NumCPU()` and uses all available cores.
- **Live PoW progress** (tries, hashrate, rough ETA) while searching (optional).
- **Live cooldown countdown** (second‑by‑second) instead of a silent sleep (normal mode).
- **Session statistics** (credits earned, runtime, credits/hour, average PoW rate, solves).
- Respects cooldown and daily earn cap exposed by the server (normal mode).
- **Extreme Mode**:
  - Uses a separate challenge endpoint with higher difficulty and no cooldown.
  - Server enforces its own “extreme” daily cap, independent from normal mining.
- Can optionally stop automatically when the (normal) daily cap is reached.
- **Graceful shutdown (Ctrl+C / SIGTERM):** best‑effort call to `POST /cancel_pow` to release the current IP mining lock.

---

## Prerequisites

- Go 1.20+ (older versions will likely work too).
- Network access to the faucet backend  
  (e.g. `https://hashcash-pow-faucet.dynv6.net/api` or `http://127.0.0.1:8000`).
- A valid **private key** exported from the web interface of the faucet.

You can find your private key in the web UI:

1. Open the Hashcash PoW Faucet in your browser.
2. Either create a new account (signup PoW) or import an existing key.
3. Use **“Export private key”** to copy it from the input box.

---

## Building

Save the miner source as `HCC-cli-miner.go`  
(or name it `main.go` inside its own folder).

Then run:

```bash
go build -o HCC-cli-miner HCC-cli-miner.go
```

This produces a binary called `HCC-cli-miner` (or `HCC-cli-miner.exe` on Windows).

Alternatively, if the file is named `main.go`:

```bash
go build
```

For cross‑compilation (examples):

```bash
# Linux amd64 from Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o HCC-cli-miner_linux_amd64 HCC-cli-miner.go

# Windows amd64 from Linux
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -o HCC-cli-miner_win_amd64.exe HCC-cli-miner.go
```

---

## Usage

Basic usage (public demo backend):

```bash
./HCC-cli-miner -url https://hashcash-pow-faucet.dynv6.net/api -key "YOUR_PRIVATE_KEY"
```

### Common flags

- `-url`  
  Base URL of the faucet API  
  (default: `https://hashcash-pow-faucet.dynv6.net/api`).

- `-key`  
  Your faucet private key (**required**). This is the same secret you see in the web UI.

- `-workers`  
  Number of PoW worker goroutines.  
  - `0` ⇒ auto‑detect (`runtime.NumCPU()`) and use all available cores.  
  - `>0` ⇒ fixed number of workers.  
  Example: `-workers 8` on an 8‑core CPU.
  
- `-stop-at-cap`  
  Whether to stop when the **normal** daily earn cap is reached (default: `true`).  
  Set to `false` if you want the miner to keep running even after the server reports that the normal daily cap has been reached. Note that the backend will not award more credits beyond that cap.

- `-progress`  
  Show a live PoW progress line (tries, hashrate, ETA) while searching (default: `true`).

- `-progress-interval`  
  Progress update interval in seconds (default: `2`).

- `-extreme`  
  Enable **Extreme Mode** (default: `false`).  
  - Uses `/challenge_extreme` with a higher difficulty and no cooldown.  
  - The server applies a separate daily cap for extreme mining.  
  - Normal `-stop-at-cap` logic only applies to the normal mode cap; the extreme cap is enforced on the server and the miner stops when that error is detected.

- `-potato`  
  Enable **Potato Mode** (default: `false`).  
  - Uses `/challenge_potato` with a lower difficulty and higher cooldown.  
  - The server applies the normal daily cap for potato mode. Usage of potato mode is discouraged for normal PCs due to the higher cooldown time. 


### Examples

Normal mode, public backend, auto workers:

```bash
./HCC-cli-miner \
  -url https://hashcash-pow-faucet.dynv6.net/api \
  -key "YOUR_PRIVATE_KEY"
```

Normal mode, local backend, explicit workers:

```bash
./HCC-cli-miner \
  -url http://127.0.0.1:8000 \
  -key "YOUR_PRIVATE_KEY" \
  -workers 8
```

Extreme Mode, public backend, auto workers:

```bash
./HCC-cli-miner \
  -url https://hashcash-pow-faucet.dynv6.net/api \
  -key "YOUR_PRIVATE_KEY" \
  -extreme
```

---

## How it works

1. **Fetch account state – `/me`**  
   The miner first calls `/me` to fetch:
   - your current credits,
   - how many credits you’ve earned today (normal mode),
   - the normal daily earn cap,
   - the current cooldown status and server time.

2. **Cooldown handling (normal mode)**  
   In normal mode, if the server reports a future `cooldown_until`, the miner waits until
   this time is reached before attempting another claim.  
   In **Extreme Mode**, the miner skips cooldown checks – the server enforces the extreme cap on its side.

3. **Request challenge – `/challenge` or `/challenge_extreme`**  
   When allowed, the miner requests a PoW challenge:
   - Normal mode: `POST /challenge` with `{"action": "earn_credit"}`.  
   - Extreme mode: `POST /challenge_extreme` with `{"action": "earn_extreme"}`.  

   The server responds with:
   - a `stamp` string,
   - a `bits` difficulty (higher in Extreme Mode),
   - and a server signature `sig`.

4. **Solve PoW locally**  
   The miner runs SHA‑256 over `stamp|nonce` with multiple worker goroutines,
   each checking nonces in its own sequence.  
   It searches for a nonce such that the hash has at least `bits` leading zero bits.

5. **Submit solution – `/submit_pow`**  
   Once a valid nonce is found, the miner posts it back to `/submit_pow`.  
   On success, the server:
   - awards credits,
   - updates the cooldown (normal mode),
   - updates the normal / extreme daily counters.

   If the extreme daily cap is reached, the server responds with an error message (e.g. containing `extreme daily cap`), and the miner exits gracefully in that mode.

6. **Repeat**  
   The loop repeats until:
   - the normal daily cap is reached and `-stop-at-cap=true` (normal mode), or
   - the extreme daily cap is reached (Extreme Mode) and the miner stops, or
   - you stop the miner manually (Ctrl+C), or
   - a persistent error occurs.

7. **Ctrl+C cleanup – `/cancel_pow` (best‑effort)**  
   If you stop the miner (Ctrl+C / SIGTERM), it will call `/cancel_pow` to release the current in‑memory IP mining lock immediately, instead of waiting for the stamp TTL to expire.

---

## Example output

### Normal mode

```text
=== Hashcash PoW Faucet CLI Miner ===
Base URL: https://hashcash-pow-faucet.dynv6.net/api
Workers: 6
Mode: normal
Stop at daily cap: true
Live progress: true (interval: 2 s)
Press Ctrl+C to stop.

Account: QmExampleAddress
  Credits: 3
  Earned today: 5 / 50
[*] Mining one credit...
[+] Challenge (normal): bits=28, stamp=v1|act=earn_credit|...
[*] PoW searching... tries=812345  rate=540.2 kH/s  ETA≈0m 12s
[+] PoW solved (normal): nonce=1234567, time=18.42s, rate≈550.1 kH/s (6 workers)
[+] Submit ok: credits=4, next_seq=6
    Session: +1 credits in 0m 25s (144.00 credits/hour), avg PoW rate≈548.7 kH/s, solves=1
```

### Extreme Mode

```text
=== Hashcash PoW Faucet CLI Miner ===
Base URL: https://hashcash-pow-faucet.dynv6.net/api
Workers: 8
Mode: EXTREME (no cooldown, higher difficulty, separate daily cap)
Stop at daily cap: true
Live progress: true (interval: 2 s)
Press Ctrl+C to stop.

Account: QmExampleAddress
  Credits: 123
  Earned today: 50 / 50
[*] Mining one EXTREME credit...
[+] Challenge (EXTREME): bits=40, stamp=v1|act=earn_extreme|...
[*] PoW searching... tries=9.8e+09  rate=12500.0 kH/s  ETA≈14m 32s
[+] PoW solved (EXTREME): nonce=987654321, time=902.34s, rate≈10862.3 kH/s (8 workers)
[+] Submit ok: credits=124, next_seq=42
    Session: +1 credits in 0m 55s (65.45 credits/hour), avg PoW rate≈10500.0 kH/s, solves=1
```

(Exact numbers are just examples.)

---

## Security notes

- The miner only uses *documented* API endpoints of the faucet.
- Cooldown and caps are enforced on the server; the miner simply follows them.
- Running multiple miners with the same private key is technically possible but not recommended,
  as they will compete for the same account and may hit more cooldown / rate limits.
- Extreme Mode performs more intensive PoW:
  - Expect higher CPU load, power draw, and temperature.
  - Consider limiting workers on laptops or thermally constrained devices.
- On shutdown (Ctrl+C / SIGTERM), the miner performs a best‑effort cleanup call (`/cancel_pow`) to release the server‑side IP lock.

Keep in mind that this is an experimental faucet demo, not a production‑grade system.

---

## License

You may use, modify and integrate this miner into your own faucet experiments.  
If you publish a modified version, please clearly mark your changes and avoid
branding that could confuse users with the original Hashcash PoW Faucet demo.

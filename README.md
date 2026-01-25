# Hashcash PoW Faucet CLI Miner

This is a simple command‑line miner for the experimental **Hashcash PoW Faucet**.  
It talks to the public HTTP API (`/me`, `/challenge`, `/submit_pow`, `/cancel_pow`) and solves
Proof‑of‑Work challenges to claim credit points for a given faucet **private key**.

The miner is written in Go, uses only the standard library and supports
multiple worker threads.
---

## Features

- Connects to the faucet HTTP API (`/me`, `/challenge`, `/submit_pow`, `/cancel_pow`).
- Uses your faucet *private key* (the random token from the web UI) as bearer token.
- Multi‑threaded PoW (configurable number of workers).
- **Live PoW progress** (tries, hashrate, rough ETA) while searching (optional).
- **Live cooldown countdown** (second‑by‑second) instead of a silent sleep.
- **Session statistics** (credits earned, runtime, credits/hour, average PoW rate, solves).
- Respects cooldown and daily earn cap exposed by the server.
- Can optionally stop automatically when the daily cap is reached.
- **Graceful shutdown (Ctrl+C / SIGTERM):** best‑effort call to `POST /cancel_pow` to release the current IP mining lock.

---

## Prerequisites

- Go 1.20+ (older versions will likely work too).
- Network access to the faucet backend  
  (e.g. `https://hashcash-pow-faucet.dynv6.net/api` or `http://127.0.0.1:8000`).
- A valid **private key** exported from the web interface of the faucet.

You can find your private key in the web UI:

1. Open the faucet in your browser.
2. Either create a new account (signup PoW) or import an existing key.
3. Use **“Export private key”** to copy it from the input box.

---

## Building

Save the miner source as `faucet_miner.go`  
(or name it `main.go` inside its own folder).

Then run:

```bash
go build -o faucet_miner faucet_miner.go
```

This produces a binary called `faucet_miner` (or `faucet_miner.exe` on Windows).

Alternatively, if the file is named `main.go`:

```bash
go build
```

---

## Usage

Basic usage (public demo backend):

```bash
./faucet_miner -url https://hashcash-pow-faucet.dynv6.net/api -key "YOUR_PRIVATE_KEY"
```

Common flags:

- `-url`  
  Base URL of the faucet API (default: `https://hashcash-pow-faucet.dynv6.net/api`).

- `-key`  
  Your faucet private key (required). This is the same secret you see in the web UI.

- `-workers`  
  Number of PoW worker goroutines (default: `4`).  
  Higher values can increase hashrate on multi‑core CPUs.

- `-stop-at-cap`  
  Whether to stop when the daily earn cap is reached (default: `true`).  
  Set to `false` if you want the miner to keep running even after a failed claim, but
  note that the backend will not award more credits beyond the cap.

- `-progress`
  Show a live PoW progress line (tries, hashrate, ETA) while searching (default: `true`).

- `-progress-interval`
  Progress update interval in seconds (default: `2`).

Example (local backend):

```bash
./faucet_miner -url http://127.0.0.1:8000 -key "YOUR_PRIVATE_KEY" -workers 8
```

Example (public demo backend):

```bash
./faucet_miner -url https://hashcash-pow-faucet.dynv6.net/api -key "YOUR_PRIVATE_KEY" -workers 6
```

---

## How it works

1. **Fetch account state – `/me`**  
   The miner first calls `/me` to fetch:
   - your current credits,
   - how many credits you’ve earned today,
   - the daily earn cap,
   - the current cooldown status and server time.

2. **Cooldown handling**  
   If the server reports a future `cooldown_until`, the miner waits until
   this time is reached before attempting another claim.

3. **Request challenge – `/challenge`**  
   When allowed, the miner requests a PoW challenge via `/challenge`
   with `{"action": "earn_credit"}`.  
   The server responds with:
   - a `stamp` string,
   - a `bits` difficulty,
   - and a server signature `sig`.

4. **Solve PoW locally**  
   The miner runs SHA‑256 over `stamp|nonce` with multiple worker goroutines,
   each checking nonces in its own sequence.  
   It searches for a nonce such that the hash has at least `bits` leading zero bits.

5. **Submit solution – `/submit_pow`**  
   Once a valid nonce is found, the miner posts it back to `/submit_pow`.
   On success, the server:
   - awards credits,
   - updates the cooldown,
   - updates the daily cap status.

6. **Repeat**  
   The loop repeats until:
   - the daily cap is reached (if `-stop-at-cap=true`), or
   - you stop the miner manually (Ctrl+C), or
   - a persistent error occurs.

7. **Ctrl+C cleanup – `/cancel_pow` (best‑effort)**  
   If you stop the miner (Ctrl+C / SIGTERM), it will call `/cancel_pow` to release the current in‑memory IP mining lock immediately, instead of waiting for the stamp TTL to expire.

---

## Example output

A typical run might look like this:

```text
=== Hashcash PoW Faucet CLI Miner ===
Base URL: https://hashcash-pow-faucet.dynv6.net/api
Workers: 6
Stop at daily cap: true
Live progress: true (interval: 2 s)
Press Ctrl+C to stop.

Account: QmExampleAddress
  Credits: 3
  Earned today: 5 / 50
[*] Mining one credit...
[+] Challenge: bits=24, stamp=earn|ts=...
[*] PoW searching... tries=812345  rate=540.2 kH/s  ETA≈0m 12s
[+] PoW solved: nonce=1234567, time=18.42s, rate≈550.1 kH/s (6 workers)
[+] Submit ok: credits=4, next_seq=6
    Session: +1 credits in 0m 25s (144.00 credits/hour), avg PoW rate≈548.7 kH/s, solves=1
```

---

## Security notes

- The miner only uses *documented* API endpoints of the faucet.
- Cooldown and caps are enforced on the server; the miner simply follows them.
- Running multiple miners with the same private key is technically possible but not recommended,
  as they will compete for the same account and may hit more cooldown / rate limits.
- On shutdown (Ctrl+C / SIGTERM), the miner performs a best‑effort cleanup call (`/cancel_pow`) to release the server‑side IP lock.

Keep in mind that this is an experimental faucet demo, not a production‑grade system.

---

## License

You may use, modify and integrate this miner into your own faucet experiments.  
If you publish a modified version, please clearly mark your changes and avoid
branding that could confuse users with the original Hashcash PoW Faucet demo.

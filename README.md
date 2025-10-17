SPA PQ Single Packet Authorization (Standalone)

Move to CLI only tool for broad compatibility

Overview
- Standalone SPA components:
  - Knocker (`spa-knocker`) sends a Kyber/ML-KEM-768 + HMAC SPA packet.
  - Doorman (`spa-doorman`) validates SPA and temporarily opens WireGuard via nftables set membership with timeout.
- Goal: provide a minimal, portable pair you can move to its own repo.

Features
- Post-quantum KEM (ML‑KEM‑768, aka Kyber768) for ephemeral key agreement.
- HMAC‑SHA256 over PSK + nonce + timestamp.
- Replay protection with nonce+timestamp window and in‑memory TTL cache.
- Two backends:
  - nftables integration via timed set entries (Linux).
 - UDP proxy backend for local port doormanning (cross-platform: Linux/macOS/Windows).

Layout
- `knocker/` — Rust CLI client (`spa-knocker`).
- `doorman/` — Rust daemon (`spa-doorman`) with:
  - `run` (Linux): validates SPA and adds IPs to an nftables set with timeout.
  - `run-proxy` (all platforms): validates SPA and proxies UDP between clients and an upstream service only when allowed.
- `nftables/allow-set.nft` — example nftables set and match for WireGuard UDP.
- `systemd/spa-doorman.service` — example unit to run the doorman.
- `AGENTS.md` — concise contributor notes for this standalone.

Quick Start
1) Build
   - Doorman: `cd doorman && cargo build --release`
   - Knocker: `cd ../knocker && cargo build --release`

2) Generate keys and PSK (on the router/host running doorman)
   - `./doorman/target/release/spa-doorman gen-keys --priv-out /etc/spa/priv.bin --pub-out /etc/spa/pub.bin`
   - Generate a 32‑byte PSK and store it (mode 0600):
     - `head -c 32 /dev/urandom > /etc/spa/psk.bin`

3) Prepare nftables (root)
   - Ensure table and set exist; example uses `table inet fw4` and set `wg_spa_allow`.
   - Example include (adjust `WG_PORT` and table name to your distro): see `nftables/allow-set.nft`.
   - Load/merge example: `nft -f nftables/allow-set.nft` (idempotent if included appropriately).

4a) Run doorman with nftables (Linux)
   - Example: `sudo ./doorman/target/release/spa-doorman run \
       --listen 0.0.0.0:62201 \
       --wg-port 51820 \
       --kem-priv /etc/spa/priv.bin \
       --psk-file /etc/spa/psk.bin \
       --open-secs 45 \
       --window-secs 30 \
       --nft-family inet \
       --nft-table fw4 \
       --nft-set wg_spa_allow`

4b) Run doorman as a UDP proxy (cross‑platform)
   - Validates SPA on `--spa-listen`, and gates a local UDP service by proxying only for allowed clients.
   - Example: `./doorman/target/release/spa-doorman run-proxy \
       --spa-listen 0.0.0.0:62201 \
       --kem-priv /etc/spa/priv.bin \
       --psk-file /etc/spa/psk.bin \
       --open-secs 45 \
       --window-secs 30 \
       --proxy-listen 0.0.0.0:51820 \
       --upstream 127.0.0.1:51820`
   - Notes:
     - Works on Linux, macOS, and Windows without admin privileges.
     - For WireGuard, set `--proxy-listen` to your public UDP port and `--upstream` to the actual service address (often `127.0.0.1:51820`).

5) Configure and run knocker from a client
   - Create `knocker/spa-knocker.json` from the example and fill values:
     - `router_host`: hostname/IP of the router
     - `spa_port`: SPA UDP port (default 62201)
     - `wg_port`: WireGuard UDP port (e.g., 51820)
     - `kem_pub_b64`: base64 of `/etc/spa/pub.bin` (router’s public key)
     - `psk_b64`: base64 of the shared PSK (the same 32‑byte secret)
   - Run: `./knocker/target/release/spa-knocker --config knocker/spa-knocker.json`

Security Notes
- Keep `/etc/spa/priv.bin` and `/etc/spa/psk.bin` secret (0600). Do not commit secrets.
- Doorman only adds IPs to a pre‑existing nft set with timeout; it does not flush rules.
- Time windows are enforced; ensure host clocks are reasonably in sync.

systemd (optional)
- Edit `systemd/spa-doorman.service` ExecStart to match your paths, then:
  - `sudo cp systemd/spa-doorman.service /etc/systemd/system/spa-doorman.service`
  - `sudo systemctl daemon-reload && sudo systemctl enable --now spa-doorman`

Client Config Example
- See `knocker/spa-knocker.json.example`.

Stand Up
- Build doorman: `cd doorman && cargo build --release`
- Build knocker: `cd knocker && cargo build --release`
- Generate keys: `./doorman/target/release/spa-doorman gen-keys --priv-out /etc/spa/priv.bin --pub-out /etc/spa/pub.bin`
- Create PSK (32 bytes): `head -c 32 /dev/urandom > /etc/spa/psk.bin`

Replay Cache
- Default capacity: 4096 entries. TTL approximately `max(60s, open_secs + 2*window_secs)`.
- Memory bounds: each entry stores IPv4 + nonce(16) + timestamp + overhead; tune via future flags if needed.

Logging
- JSONL on stderr by default: `{ts, client_ip, decision, reason, opens_for_secs}`.
- Options: `--obfuscate-ip` (hash client IP), `--log-file <path>` to write logs securely.

nftables Integration
- Pre-create `table inet fw4` and a timed set (e.g., `wg_spa_allow`). Doorman only adds elements with timeouts; it never flushes rules.
- Validate setup: `spa-doorman nft-validate --nft-family inet --nft-table fw4 --nft-set wg_spa_allow`.
- Integrate rules into an existing ruleset; avoid replacing `fw4`. See `nftables/allow-set.nft` and nftables/README.md for safe include patterns.

Doorman flags
- `--rate-pps <u32>`: max knocks per second per IP (default 10)
- `--rate-burst <u32>`: burst size for per-IP limiter (default 20)
- `--log-file <path>`: write JSONL logs to a file instead of stderr
- `--obfuscate-ip`: hash the client IP in logs
- `--verbose` / `-v` (repeatable): include error details in drop logs
- `--quiet`: suppress allow/info logs (drop/error still logged)

Examples
- Rate limit and log to file:
  - `sudo ./doorman/target/release/spa-doorman run \
       --listen 0.0.0.0:62201 \
       --kem-priv /etc/spa/priv.bin \
       --psk-file /etc/spa/psk.bin \
       --nft-family inet --nft-table fw4 --nft-set wg_spa_allow \
       --rate-pps 10 --rate-burst 20 \
       --log-file /var/log/spa-doorman.jsonl`
- Obfuscate IPs and be quiet:
  - `sudo ./doorman/target/release/spa-doorman run \
       --obfuscate-ip --quiet`

Validate nftables
- Check existence of family/table/set:
  - `spa-doorman nft-validate --nft-family inet --nft-table fw4 --nft-set wg_spa_allow` → prints `ok` on success

License
- Inherit your repository’s license policy. No license file shipped here.
- Windows (RunProxy)
- Secure secret files with ACLs so only Administrators/System (or your service user) can read them. Example commands (run in an elevated shell):
  - `icacls C:\\spa\\priv.bin /inheritance:r`
  - `icacls C:\\spa\\priv.bin /grant:r Administrators:F System:F`
  - `icacls C:\\spa\\psk.bin /inheritance:r`
  - `icacls C:\\spa\\psk.bin /grant:r Administrators:F System:F`
  - If running as a specific user account for a Windows service, grant that user `R` on both files.

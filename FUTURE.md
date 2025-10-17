PqSPA Roadmap and Pending Changes

Scope
- Applies to this PqSPA bundle only. Open-source, cross-platform CLI (Mac/Linux/Windows).

Status Snapshot (v1, IPv6 first pass)
- Doorman
  - Rate limiter + logger wired; per-packet errors log-and-continue.
  - NftValidate subcommand available; prints "ok" when family/table/set exist.
  - Replay cache and RunProxy authorization generalized to IpAddr; RunProxy authorizes IPv6 in-memory.
  - Primary IPv6 path: parsing + replay detection work; nft insertion for v6 deferred (logs and continues).
- Knocker
  - v1 packets only. IPv6 destination support pending.
- Systemd/Windows
  - systemd unit validated (no deprecated flags). Windows icacls guidance pending in README.

Next Implementation Steps (v1 compatible)
1) Doorman: IPv4/IPv6 nft sets + flags
   - Flags: --nft-set-v4 (default wg_spa_allow_v4), --nft-set-v6 (default wg_spa_allow_v6), keep --nft-set for IPv4-only.
   - On allow:
     - IPv4: insert into v4 set; fallback to legacy --nft-set; else log drop "ipv4 set not configured".
     - IPv6: insert into v6 set; if missing, log drop "ipv6 set not configured".
2) Doorman: nft-validate updates
   - Extend to accept optional --nft-set-v4/--nft-set-v6; validate whichever are provided; legacy --nft-set remains.
3) Doorman: dual-stack bind (run, run-proxy)
   - Attempt bind on "::" with v4-mapped allowed; fallback to IPv4-only if v6 bind fails. No behavior change on failure.
4) Knocker: IPv6 sockets
   - Resolve/connect IPv6 destinations; keep v1 layout; write client_ip(u32)=0 for IPv6.
5) Docs (README)
   - Doorman flags: --rate-pps, --rate-burst, --log-file, --obfuscate-ip, --verbose, --quiet.
   - nftables examples for dual-stack sets/rules and validation commands.
   - Windows icacls examples to secure /etc/spa equivalents (priv.bin, psk.bin).

Operational Guarantees
- Safety first: fail fast at startup (bind, keys/psk, nft-validate). Per-packet failures never crash the daemon.
- nftables: only add set elements with timeout; never flush rulesets.
- No secrets in repo; treat /etc/spa/*.bin as sensitive.

Protocol v2 Vision (post v1 hardening)
- Goals
  - Remove legacy client_ip field; server authorizes by UDP source address only.
  - Authenticate before decapsulation: HMAC-before-decap using PSK-derived key.
  - Optional forward secrecy and extensibility via KEM for payload.
- Sketch
  - Derive HMAC key via HKDF(PSK, ver || nonce || ts).
  - Compute/verify HMAC over ver || nonce || ts (and optional payload hdrs) before KEM decap.
  - Maintain versioned packet header; bump to ver=2 and support dual-run period.
- Migration
  - Ship doorman/knocker with dual support (v1+v2) for a deprecation window.
  - Add feature flag to disable v1 once v2 rollout completes.

Fast Test Environment (repo-local)
- nftables scripts (idempotent): create v4/v6 sets with timeout; add rules; remove helpers.
- Non-root dev shim: a dry-run mode or mock nft command for CI and Windows.
- Quick runners: cargo run doorman/knocker examples with sample keys; optional cargo watch.
- Integration smoke: send a sample knock and assert log outputs and (mock) nft insertion.

Notes and Constraints
- Keep #![forbid(unsafe_code)], minimal changes, and small codebase.
- Do not reintroduce removed flags (e.g., --wg-port, --nft-chain).
- Predictable + idempotent behavior; re-runs are safe.

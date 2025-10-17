Scope
- Applies to this `PqSPA` bundle only.

Principles
- Core Design Vision: Open-Source widely compatible (Mac,Lin,Win) PqSPA CLI tool
- Safety first: fail fast, validate inputs early, avoid partial state.
- Explicit over implicit: surface assumptions and preconditions in code and docs.
- Strongly type code at all times with verbosity when needed but NEVER bloat a fn or call with added whitespace or params
- Least privilege/Zero Trust Architecture: no secret logging; secrets live outside repo and should be ephemeral on runtime anyway.
- Predictable + idempotent: re‑runs do not cause destructive side effects.
- Small codebase (under 1mb) makes broad compatibilty easy and trackable for a single dev
- Never break from the core design scope (Open-Source widely compatible PqSPA CLI tool)
- Choose the most secure yet simplest option when presented with choices

Coding
- Rust crates are `doorman/` and `knocker/` with `#![forbid(unsafe_code)]`.
- Do not change protocol defaults without updating README.
- Keep changes extra small and focused; update README when flags/behavior change.
- Write minimal, elegant changes without adding out of scope code.
- Avoid unsafe code at all times double checking out GCs are running properly.
- All code is carefully vetted to assure ultrafast and ultrasecure usage. 
- remove any references to 'wg' or wireguard we must be able to overlay if we want but not directly depend


Operational
- nftables: only add elements with timeout to a pre‑created set; do not flush rulesets.
- systemd: keep units simple; ensure ExecStart matches binary path and args.
- No secrets are tracked here; treat `/etc/spa/*.bin` as sensitive.

Docs
- Keep `README.md` as source of truth for usage, flags, and examples.
- `README.md` should be updated anytime a change is made that effects the runtime protocols
- Avoid bulletpoints and write with a human natural cadence


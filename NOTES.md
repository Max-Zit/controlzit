# ControlZit — working notes

Product: **ControlZit** (MaxZit RMM). Name confirmed by Stefan 2026-10-20.
Repository: github.com/Max-Zit/controlzit — **private** until Stefan says to make it public.
Local path: C:\Users\Mili\Ai\rmm

## Ground rules
- Totally separate from BackupZit (no shared code/agent/database); ideas may be re-implemented.
- No dependency on other open-source products/services; plain Go libraries are fine.
- Commits as stefanzeljkic only, no AI attribution; stage explicit paths.
- Secrets only in credentials.txt (gitignored), never printed or committed.

## Decisions
- 2026-10-20: name ControlZit; private GitHub repo Max-Zit/controlzit.
- 2026-10-20: license AGPLv3 (like BackupZit) + paid support; add LICENSE before going public.
- 2026-10-20: architecture confirmed (Go server + PostgreSQL, Go Windows agent, outbound TLS, pinned cert).
- 2026-10-20: agent port and management console port MUST be separate listeners so the agent port can be isolated on the firewall; expose both (address/port, LAN-only, allowed IP ranges) as options in Settings.
- 2026-10-20: feature order confirmed: 1 server skeleton, 2 agent/inventory, 3 monitoring/alerts, 4 remote actions, 5 patching, 6 remote desktop, 7 reports.
- Brand: same design as BackupZit/MaxZit (indigo square, white line symbol, Inter SemiBold, "Zit" in indigo). brandgen got a `controlzit [a|b|c]` mode (maxzit-brand/tools/brandgen/controlzit.go).

## Open questions for Stefan
- Keep lab CT 9600 (cz-server) and the ControlZit agent on bz-win11 for the next steps? (assumed yes until he says otherwise)
- Order after the MSI: feature 3 (monitoring/alerts) or 4 (remote actions)?

## Status (2026-10-21, afternoon)
- Feature 1 server skeleton: done (see git log); dev flag `--dev-no-2fa` (only with `--dev-embedded-db`) because Stefan has no authenticator for the dev console yet — the dev console runs with it (banner shown).
- **Feature 2 agent: enrollment, online status, inventory — done and tested for real.**
  - Protocol (internal/proto): agent makes an ed25519 key + self-signed client cert; POST /agent/v1/enroll over TLS with the cert, pinning the server's agent-cert SHA-256; server consumes the token atomically and stores the key (devices.key_id). Afterwards the TLS client certificate is the identity (agent listener uses tls.RequestClientCert; unknown key → 401). WebSocket /agent/v1/connect (github.com/coder/websocket): hello → welcome (heartbeat 60 s, inventory 12 h), heartbeat, inventory, inventory.request. Server drops silent agents after 3 min; agent reconnects with backoff + jitter.
  - Agent (cmd/controlzit-agent): enroll/run/install/uninstall/status/inventory/version; Windows service ControlZitAgent (auto start, delayed, restart on failure); data dir %ProgramData%\ControlZit Agent with DACL SYSTEM + Administrators (+ the running user if not SYSTEM); agent.log with rotation.
  - Inventory (internal/agent/inventory.ps1, built-in PowerShell/CIM/registry): OS, build, display version, hardware, CPU, RAM, disks, network, installed software (registry), logged-on user, BitLocker (needs SYSTEM/admin), Defender, firewall profiles, pending reboot.
  - Console: Devices page (search), devices on the site page, device page (system, hardware, security, disk bars, network, software search), refresh inventory, remove device (closes the channel, key stops working), install instructions with server URL + fingerprint (+ token right after creating it). Static files get ?v=hash (browser cache).
  - Tests: e2e agent↔server over real TLS (wrong pin, wrong token, single-use token, hello/inventory stored, console shows it, refresh reaches agent, delete disconnects), client cert required; agent unit tests. vet/staticcheck/gosec clean.
  - Real test: server in **Proxmox CT 9600 "cz-server" (Debian 12, 192.168.101.179, PostgreSQL 15, systemd unit controlzit)**, agent as a service on **bz-win11** (device #1 "DESKTOP-NBB66OQ" in "MaxZit Lab / Lab Hyper-V"): enrolled, online, full inventory incl. BitLocker; stop service → Offline, start → Online; server restart → agent reconnected in seconds. Lab server credentials + TOTP secret: rmm/.devdata/lab-server.txt (gitignored). Stefan's PC firewall blocks inbound 18444 (no admin), so agents on VMs must use the CT server.
  - Not yet: MSI installer, signed commands, signed self-update, Linux agent, uninstall cleanup of the data dir.

## Next steps (resume here)
1. MSI (WiX 5.0.2, as BackupZit): installs to Program Files\ControlZit Agent, ServiceInstall ControlZitAgent, properties SERVER_URL, FINGERPRINT, TOKEN → custom action runs `controlzit-agent enroll` before the service starts; upgrade keeps the enrollment; uninstall removes service (+ optional data). Test silent install on bz-win11 and via GPO on bz-dc1 domain (ask Stefan before changing AD).
2. Server command key (ed25519) + agent verifies signed commands; then feature 3 (monitoring/alerts) or 4 (remote actions) — ask Stefan for order.
3. Reverse proxy / ACME / uploaded console certificate; docs pages in the console.

## Known gaps / later
- No reverse-proxy support (X-Forwarded-For) yet; no uploaded/ACME console certificate yet.
- Audit chain head not anchored outside the DB yet (a DB admin could rewrite the whole chain).
- A stolen initial password lets an attacker enroll their own TOTP before the real user does (inherent to first sign-in; admins should hand out initial passwords privately). Later: optional enrollment link with expiry.
- Graceful shutdown on Windows when killed: embedded PG keeps running (dev only).
- Docs pages in the console (like BackupZit doc_*.html) not started.


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
- 2026-10-21: Stefan wants remote desktop "like TeamViewer" and a file manager that works without a desktop session. Proposed order: MSI → signed server commands → file manager → remote desktop → monitoring/alerts (confirm).
- 2026-10-21: code must be original (no copied foreign code); dependencies only with AGPL-compatible licenses — current: pgx MIT, coder/websocket ISC, golang.org/x/{crypto,sys,image} BSD-3, rsc.io/qr BSD-3, embedded-postgres MIT (dev/tests only), go-winres (build tool), WiX 5 MS-RL (build tool). Make THIRD_PARTY_LICENSES before going public.
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
  - Not yet: signed commands, signed self-update, Linux agent.

- **MSI done (2026-10-21):** packaging/windows/agent.wxs + build-msi.ps1 (WiX 5.0.2, Util+UI ext; images from tools/msiart; ProgramFilesControlZit Agent, service ControlZitAgent LocalSystem auto + restart on failure). One enrollment code CZ1-<base64url {u,f,t}> (console shows it once after "Create enrollment code", plus msiexec + manual commands and a download link for <data-dir>/downloads/controlzit-agent-x64.msi). Properties ENROLLCODE or SERVER_URL/FINGERPRINT/TOKEN, FORCEENROLL. Custom action `enroll --if-not-enrolled --pending-ok` as SYSTEM before StartServices (HideTarget: code not in the MSI log); unreachable server → pending-enrollment.json, the service finishes it with backoff; refused token → install fails (1603); --force keeps the old enrollment until the new one succeeds (bug found in test and fixed); uninstall runs `forget` (config, key, registry marker HKLMSOFTWAREMaxZitControlZit Agent; log stays). Tested on bz-win11: silent install, upgrade 0.1.0→0.1.1→0.1.2 keeps the device, uninstall clean, pending enrollment finished 11 s after the server came back, bad code with FORCEENROLL → 1603 and the agent stays enrolled. Interactive dialog not tested visually yet (PowerShell Direct has no desktop).
- Sidebar shows server time zone + ticking clock (as BackupZit). Stefan: reuse BackupZit solutions where they fit.

- **Signed commands + file manager done (2026-10-21):** server command key data-dir/tls/command.key (ed25519); agents get the public key at enrollment (or once via welcome over the pinned channel for older agents — tested on bz-win11 0.1.2→0.1.3); every command is bound to the agent ID, expires (≤30 min, ±2 min skew), is accepted once (replay cache) and must verify, else refused — e2e test with a changed server key. File manager (Devices → Files): drives with space, browse (hidden dimmed, 5000 entries max), download (1 MB chunks, streams any size), upload (multipart → 1 MB chunks into .czpart, rename on the last; up to 4 GB), new folder, rename, delete (recursive for folders); agent refuses relative/UNC/device paths, ADS, and deleting or renaming drive roots and system folders (Windows, Program Files, ProgramData, Users); technician role; every operation audited (file.list/download/upload/mkdir/rename/delete). Tested for real on bz-win11 through the lab server (3 MB roundtrip identical, C:Windows delete refused), UI checked at desktop and 375 px.

- **Remote desktop v1 done (2026-10-21):** internal/rd (GDI capture of the virtual screen + cursor, 64 px tile diff, JPEG strips, credit-based flow control, scan-code keyboard, absolute mouse, Unicode text, SendSAS, notice banner excluded from capture), helper `controlzit-agent rdhelper` started by the service in the console session with a SYSTEM token (token via stdin, never on the command line; redacted in logs), second WebSocket /agent/v1/stream (mTLS + one-time session token), console relay /devices/{id}/rd/ws (Origin checked), viewer /devices/{id}/rd (static/rd.js), audit rd.start/rd.end. Tested: own PC desktop in the preview (1920×1080 live), bz-win11 as SYSTEM with nobody signed in → Winlogon lock/sign-in screen captured, Space opened the password box, mouse click opened the accessibility menu, helpers exit after the session. tools/rdclient = headless viewer for lab tests (writes a PNG).
- Not yet verified: banner and the Default desktop with a signed-in user on a VM (I do not type Windows passwords — Stefan can sign in, or test with the viewer himself), UAC switch while connected, Ctrl+Alt+Del effect (may need the SoftwareSASGeneration policy), multiple monitors.
- 2026-10-21: at Stefan's request the lab server (CT 9600) also runs with --dev-no-2fa (password only, red banner, audited at start). Remove the flag from /etc/systemd/system/controlzit.service when testing is over.
- Stefan can try the lab console in his own browser: https://192.168.101.179:8443 (accept the self-signed certificate), credentials + 10 recovery codes (instead of an authenticator) in rmm/.devdata/lab-server.txt.

- **Monitoring and alerts v1 done (2026-10-21):** agent metrics with heartbeats (CPU via GetSystemTimes, memory, fixed disks; stopped automatic services every 5 min; Defender/firewall/pending restart every 15 min); server keeps latest metrics + 7 days of CPU/memory samples; rules every minute (sustained CPU/memory, disk % or GB for disks > 2× the limit, offline, restart pending + uptime, Defender off, firewall profile off, watched services); alerts open/refresh/resolve, acknowledge, offline devices keep their other alerts; emails over SMTP (STARTTLS/TLS/none, password encrypted, test email) on open and optionally resolve; Alerts page + nav badge + overview tile, device page shows open alerts, current load and stopped services; Settings → Monitoring and alerts. Tested for real: bz-win11 + lab server + Mailpit (192.168.101.102:8025): test mail, Spooler stopped → critical alert + email in ~6 min, started → resolved email; a false low-disk alert on the 4 GB E: drive led to the rule fix.
- Remote desktop with a signed-in user works (Stefan signed in on bz-win11; desktop captured as SYSTEM). The notice is excluded from the capture by design, so I could not see it; the Hyper-V thumbnail is black.

- 2026-10-21: folder download as streamed ZIP (Files → folder menu "Download as ZIP" and "Download this folder (ZIP)"); links/junctions skipped and listed in _controlzit-skipped.txt; limits 50000 files, depth 32; tested on bz-win11 (31 MB in 4.9 s, junctions in Documents skipped). Device page header with large Remote desktop / Files buttons.

## Next steps (resume here)
1. Remote desktop v2: DXGI Desktop Duplication (faster), monitor choice, clipboard both ways, scaling/bandwidth tuning, session recording option; verify banner + UAC with a signed-in user.
2. Fresh Windows test VM on Proxmox (VMID 96xx) for interactive MSI tests.
3. Monitoring and alerts (feature 3), patching (5), reports (7).
4. Reverse proxy / ACME / uploaded console certificate; docs pages in the console.

## Known gaps / later
- No reverse-proxy support (X-Forwarded-For) yet; no uploaded/ACME console certificate yet.
- Audit chain head not anchored outside the DB yet (a DB admin could rewrite the whole chain).
- A stolen initial password lets an attacker enroll their own TOTP before the real user does (inherent to first sign-in; admins should hand out initial passwords privately). Later: optional enrollment link with expiry.
- Graceful shutdown on Windows when killed: embedded PG keeps running (dev only).
- Docs pages in the console (like BackupZit doc_*.html) not started.


## Remote desktop plan (draft, 2026-10-21)
- The service runs as SYSTEM in session 0 and cannot see the desktop. It starts a helper (same exe, `controlzit-agent rdhelper`) in the console/user session with a SYSTEM token whose session ID is set (CreateProcessAsUser), so it can also show the sign-in screen and UAC prompts (like TeamViewer). Helper ↔ service: named pipe with an ACL for SYSTEM only.
- Capture: DXGI Desktop Duplication (dirty rectangles), GDI BitBlt fallback (Server 2012 R2, RDP sessions). Encoding without external codecs: 64×64 tiles, only changed tiles, JPEG (stdlib) with adaptive quality, lossless PNG option for text; cursor separately.
- Transport: a second WebSocket per session from the agent (/agent/v1/stream, mTLS + one-time session token from the signed `rd.start` command), binary frames; the console relays to the browser over a WebSocket on the console listener (same origin, session cookie, CSRF Origin check). The control channel stays free.
- Browser viewer: canvas, JS file under CSP 'self'; mouse, keyboard (scan codes), Ctrl+Alt+Del button (SendSAS), clipboard text, monitor switch, quality/scale, full screen.
- Security: technician role; signed command; consent prompt on the remote desktop (configurable); visible banner on the remote screen while connected; audit start/end/duration/user; session recording (video) optional later.
- Decided by Stefan 2026-10-21: no consent prompt — connect directly, but always show a notice on the remote screen that a technician is connected.

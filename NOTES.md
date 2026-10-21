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
- Pick icon a (monitor + pulse), b (circuit C) or c (control hub) — full sets in maxzit-brand/concepts/controlzit/{a,b,c}. Then copy the chosen set to maxzit-brand/controlzit-logo and into the repo.

## Status (2026-10-21)
- Logo A (monitor + pulse) chosen; full set in maxzit-brand/controlzit-logo and repo brand/.
- **Feature 1 server skeleton: done except the agent MSI** (the MSI needs the agent, feature 2).
  - internal/auth, netacl, store, tlsutil, testdb as before (tested).
  - internal/web console: first-run setup with one-time token (data-dir/setup-token.txt), sign-in, mandatory TOTP enrollment + 10 recovery codes, 2FA with replay protection, session rotation after 2FA, `__Host-` cookie, idle/absolute timeouts, brute-force blocks (progressive, in DB, loopback exempt), CSRF Origin/Referer/Sec-Fetch-Site check, CSP without inline code, security headers.
  - Customers → sites, enrollment tokens (shown once, hashed, expiry + max uses, revoke), users with roles admin/technician/readonly + per-customer access, must-change-password, admin 2FA reset, own account (password, recovery codes, sessions), audit log page with chain verification, Settings → Network and access (separate console/agent listen addresses, both allow-lists, public agent URL, refuses a list that locks out the saving admin), Settings → Sign-in and security (sessions, block policy, unblock).
  - English + Serbian (i18n/sr.json); a test fails when a UI text lacks a Serbian translation.
  - cmd/controlzit-server: two TLS listeners (agent cert separate from console cert, agents will pin its SHA-256), netacl check before TLS, TLS 1.2+, --dev-embedded-db, --dev-http (loopback only), --reset-allowlist, --unblock-ip, --mgmt-listen/--agent-listen overrides (console shows a note then).
  - Agent endpoint answers GET /agent/v1/health only.
- Tests: `go test ./...` passes (auth, netacl, store, web flows incl. setup token, 2FA, replay, CSRF, allow-list + lock-out guard, login block, roles/customer isolation, token once, i18n completeness). go vet, staticcheck, gosec (0 issues), govulncheck (no called vulns; toolchain go1.27.2) clean.
- Verified in the preview pane: setup → 2FA → overview → customer → site → token, Serbian, light + dark, 375 px (menu, no horizontal scroll), no console/CSP errors; TLS listeners checked with curl/openssl.
- Dev console: preview config "controlzit-dev" in C:\Users\Mili\Ai\.claude\launch.json (http://localhost:8095); dev credentials + TOTP secret in rmm/.devdata/dev-admin.txt (gitignored). Stopping it leaves embedded postgres running: `.devdata/pgbin/bin/pg_ctl.exe stop -D .devdata/pgdata -m fast`.

## Known gaps / later
- No reverse-proxy support (X-Forwarded-For) yet; no uploaded/ACME console certificate yet.
- Audit chain head not anchored outside the DB yet (a DB admin could rewrite the whole chain).
- A stolen initial password lets an attacker enroll their own TOTP before the real user does (inherent to first sign-in; admins should hand out initial passwords privately). Later: optional enrollment link with expiry.
- Graceful shutdown on Windows when killed: embedded PG keeps running (dev only).
- Docs pages in the console (like BackupZit doc_*.html) not started.

## Next steps (resume here)
1. Feature 2 — agent (Go, Windows service): enrollment via POST /agent/v1/enroll with token → per-agent ed25519 identity + server-signed agent certificate or key registration; agent pins the agent-endpoint certificate fingerprint; long-lived WebSocket channel; heartbeat → online status; device list per site in the console.
2. Inventory (OS, build, hardware, disks, network, software, logged-on user, uptime, BitLocker, Defender) via WMI/CIM; device page.
3. Server command signing key (ed25519) + agent verification; signed self-update.
4. MSI (WiX 5.0.2) with SERVER_URL, ENROLL_TOKEN, SERVER_FINGERPRINT properties; test on bz-win11 and a Proxmox VM (VMIDs 9600–9699).

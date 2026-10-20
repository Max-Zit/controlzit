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

## Status (2026-10-20, stopped by Stefan — resume when he says)
- Logo A (monitor + pulse) chosen; full set in maxzit-brand/controlzit-logo and repo brand/.
- DONE + tested (go test passes): internal/auth (argon2id, TOTP RFC 6238, recovery codes, tokens), internal/netacl (allow-lists, listener that refuses before TLS), internal/store (migrations 001, users/2FA, sessions, customers/sites, enrollment tokens, settings, login blocks, hash-chained audit), internal/testdb (embedded PostgreSQL for tests), internal/tlsutil (self-signed certs, fingerprint; agent cert separate from console cert).
- IN PROGRESS, not committed, does not compile yet: internal/web — written: render.go (templates, i18n, flash), server.go (Server, NetworkSettings with separate mgmt/agent listeners + validation, SecuritySettings, routes, security headers/CSP, ACL check, CSRF Origin check), login.go (sessions, setup with one-time setup token, login, 2FA, mandatory TOTP enrollment, logout, lang, loginGuard).

## Next steps (resume here)
1. internal/web: fix server.go field `tmpl map[string]*template` → `*template.Template` (import html/template); add `urlPath` helper.
2. Write pages.go (overview, customers, sites, enrollment tokens), users.go (users, account: password, recovery codes, sessions), settings.go (network: listen addresses + allow-lists, refuse a list that excludes the current client IP; security: sessions, blocks/unblock; audit page with chain check).
3. Templates (_layout.html with app/guest layouts, sidebar #0f172a, logo A inline SVG; setup, login, login2fa, enroll, recoverycodes, overview, customers, customer, site, users, user, account, audit, network, security, notfound, forbidden), static/app.css (light/dark tokens), static/app.js (theme toggle, menu, copy buttons; no inline scripts), favicon.svg; i18n/sr.json + test that every template text has a Serbian translation.
4. cmd/controlzit-server: flags --data-dir, --db, --dev-embedded-db, --dev-http (loopback only), --mgmt-listen/--agent-listen overrides, --reset-allowlist, --unblock-ip, --version; two TLS listeners with netacl.Listener; setup-token.txt on first run.
5. Web tests (setup token, login + 2FA, CSRF, ACL, lockout, roles/customer visibility), go vet, staticcheck, gosec, govulncheck; preview at desktop + 375 px, light/dark.
6. Then: agent MSI + enrollment (feature 2).

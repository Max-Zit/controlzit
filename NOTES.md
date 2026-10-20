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

## Open questions for Stefan
- License (AGPLv3 like BackupZit?) — needed before the repo goes public.
- Confirm architecture (Go server + PostgreSQL, Go Windows agent, outbound TLS with pinned cert).
- Confirm feature order (1 server skeleton → 2 agent/inventory → 3 monitoring → 4 remote actions → 5 patching → 6 remote desktop → 7 reports).
- Pick one of the 3 proposed icons (to be generated).

## Status
- Repo created (README, NOTES, .gitignore).

## Next steps
- Server skeleton: setup, admin with mandatory TOTP, argon2id, sessions, IP allow-list on the management listener, customers/sites/devices, enrollment tokens.

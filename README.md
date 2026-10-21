# ControlZit

ControlZit is a self-hosted RMM (remote monitoring and management) tool by MaxZit
for managing Windows PCs and servers: inventory, monitoring and alerts, remote
actions and scripts, patch management, remote desktop and per-customer reports.

Status: early development (private repository).

## Components
- **controlzit-server** — one Go binary with PostgreSQL: agent endpoint and a
  separate management console/API restricted to allowed IP addresses.
- **controlzit-agent** — Windows service that connects outbound only to the
  server over TLS with a pinned server certificate.

## Security model (server skeleton)
- Two listeners on different ports: the **console** (`--mgmt-listen`, default `:8443`)
  and the **agent endpoint** (`--agent-listen`, default `:8444`). Firewall them
  separately; the agent port may be public, the console should not be.
- The console accepts connections only from the allowed networks
  (Settings → Network and access; default: private ranges). The check runs at
  TCP accept, before TLS. Loopback is always allowed; if you lock yourself out,
  run `controlzit-server --reset-allowlist` on the server.
- First-run setup needs the one-time token from `<data-dir>/setup-token.txt`.
- Every account needs an authenticator app (TOTP) plus 10 recovery codes;
  passwords are argon2id; sessions are short (8 h, 30 min idle by default);
  failed sign-ins block the address (progressive).
- CSRF: state-changing requests must come from the console's own origin.
  CSP without inline scripts or styles; `__Host-` session cookie.
- Every change is written to a hash-chained audit log; the console verifies the
  chain on every view of the log.

## Development
```
go test ./...                       # needs no installed PostgreSQL (embedded)
go build -o bin/controlzit-server.exe ./cmd/controlzit-server
bin/controlzit-server.exe --dev-embedded-db --data-dir .devdata \
  --mgmt-listen 127.0.0.1:18443 --agent-listen 127.0.0.1:18444 --dev-http 127.0.0.1:8095
go run ./tools/totp SECRET          # current code of a TOTP secret (tests)
```

## Agent (Windows)
```
.\controlzit-agent.exe enroll --server https://SERVER:8444 --fingerprint <SHA-256 from the console> --token czet_…
.\controlzit-agent.exe install      # Windows service ControlZitAgent
.\controlzit-agent.exe inventory    # print what the agent reports
```
Run from an elevated prompt. The site page in the console shows the exact command.

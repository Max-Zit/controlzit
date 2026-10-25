# Security policy

## Supported versions

Security fixes are released for the newest ControlZit version. The server checks for updates and installs signed releases from *Settings → Version and updates*; agents update themselves to the server's version.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/controlzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## Security design

- The console and the agent endpoint listen on separate ports; the console accepts connections only from allowed networks, checked before TLS.
- Agents connect outbound only and pin the server certificate. Every command to an agent is signed by the server and checked by the agent.
- Two-factor sign-in (TOTP) for local and LDAP accounts, argon2id passwords, short sessions, progressive blocking of failed sign-ins, CSRF protection and a strict Content Security Policy.
- Roles (administrator, technician, read-only) and per-customer access; a hash-chained audit log.
- Root actions of the console (updates, network, time zone) go through a separate root helper with a fixed set of validated requests.
- Diagnostics remove passwords, tokens, enrollment codes and keys from everything they show or export.

## How releases are protected

- Every release has a manifest signed with the ControlZit release key (ed25519); the server, the agents and `install.sh` verify the signature and checksums before installing.
- Release packages are built from tagged commits of this repository; the appliance images carry a written source offer (`SOURCE-CODE.txt`).

## How ControlZit is tested

**On every change (GitHub Actions):** build for Linux and Windows, `go vet`, the full test suite (against an embedded PostgreSQL), staticcheck, gosec, govulncheck, Gitleaks, CodeQL, Dependabot, secret scanning and the [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Max-Zit/controlzit).

**Before releases (manually, in a test lab):** Semgrep, Trivy, an OWASP ZAP scan of the running console signed in as an administrator, OpenVAS / Greenbone and nmap against the appliance, and an end-to-end regression on real Windows and Linux machines (enrollment, monitoring, alerts, remote desktop, terminal, files, scripts, updates, roles, LDAP and SSO).

Findings are fixed before the release; accepted risks are documented in the release notes.

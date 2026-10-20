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

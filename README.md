# RMMZit — open-source, self-hosted RMM

[![Latest release](https://img.shields.io/github/v/release/Max-Zit/rmmzit?label=release)](https://github.com/Max-Zit/rmmzit/releases/latest)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue)](LICENSE)
[![Security scan](https://github.com/Max-Zit/rmmzit/actions/workflows/security.yml/badge.svg)](https://github.com/Max-Zit/rmmzit/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Max-Zit/rmmzit/badge)](https://scorecard.dev/viewer/?uri=github.com/Max-Zit/rmmzit)

**Remote monitoring and management for Windows and Linux computers, from one web console on your own server.** A free, open-source alternative to commercial RMM tools for IT departments and service providers.

RMMZit keeps an inventory of every computer, watches it and raises alerts, lets technicians work on it remotely (remote desktop, terminal, files, processes, services), runs scripts on one or many devices, installs Windows updates and software on a schedule, and sends each customer a report.

- **Your own server, your own network.** No cloud service; the console never has to be reachable from the internet. Agents connect outbound, so managed computers need no open ports.
- **Free and open source** under the AGPLv3. [MaxZit](https://github.com/Max-Zit) offers commercial support.
- **14 languages**: English, German, French, Spanish, Italian, Portuguese, Dutch, Polish, Czech, Serbian, Turkish, Russian, Chinese and Japanese — the console and its built-in user guide.

**Download:** [latest release](https://github.com/Max-Zit/rmmzit/releases/latest) · **Install:** [quick start](#installation) · **Guide:** built into the console under *Documentation*

---

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Installing agents](#installing-agents)
- [Updating](#updating)
- [Security](#security)
- [Development](#development) · [License](#license)

## Features

| Area | What you get |
|---|---|
| **Inventory** | hardware, operating system, disks, network, Defender, firewall and BitLocker state, installed software |
| **Monitoring and alerts** | CPU, memory, disk space, offline devices, stopped services, Defender and firewall off, pending restarts, disk health (SMART, RAID), network checks (ping, TCP, web and certificates) from the devices, Windows event log and process monitors; history (24 hours to 90 days) with a disk-full forecast; alerts by email, Slack, Microsoft Teams or signed webhooks |
| **Remote desktop** | in the browser, Windows and Linux (X11): sign-in and UAC screens, several monitors, text clipboard both ways, file copy with Ctrl+C / Ctrl+V, an optional notice on the remote screen |
| **Terminal and files** | a terminal in the browser (PowerShell as SYSTEM on Windows, a root shell on Linux); a file manager with upload, download and ZIP; processes and services; registry editor and scheduled tasks on Windows; restart and shutdown |
| **Scripts** | PowerShell, cmd, bash and sh on one device, many at once or on a schedule, from a script library; results per device |
| **Updates and software** | missing Windows updates and Linux packages (apt, dnf), installed by hand or on a schedule; programs through winget and optionally Chocolatey; your own MSI/EXE library deployed silently to many devices; every installed program listed and silently uninstalled; Windows event logs |
| **Reports** | per customer: devices, updates, alerts and technician work; printable or emailed every week or month |
| **Policies** | Windows Update, required software (installed automatically when missing), blocked programs, program updates with update rings, restarts with a deadline, maintenance windows, network checks, alert rules, event log and process monitors, automations and BitLocker per customer, site or device; every new customer gets a *Default* policy; the most specific assignment wins |
| **Activity** | every action on a device is a task: running, waiting (offline devices) and history, with cancel and stop |
| **BitLocker** | recovery keys collected and kept encrypted on the server, shown to administrators after a password check; switched on by policy |
| **Vulnerabilities** | installed programs checked against NVD (common Windows programs) and OSV (Debian, Ubuntu packages); per device and fleet-wide, alerts for critical ones |
| **Custom fields** | your own fields for devices and customers (asset number, warranty, contract), also through the API |
| **API** | REST API with personal tokens (role no higher than the user's), documented in the console |
| **Users** | roles (administrator, technician, read-only) and per-customer access; two-factor sign-in; Active Directory / LDAP and single sign-on (OpenID Connect, SAML) |
| **Server** | Let's Encrypt or your own certificate, signed self-update (official or testing channel), daily console backup (optionally encrypted, copied over SFTP) with restore, network and time zone from the console, diagnostics without secrets, tamper-evident audit log |
| **Deployment** | MSI with an enrollment code; a ready Group Policy startup script and Microsoft Intune Win32 app settings on every site page |

## How it works

```
                    ┌──────────────────────────────┐
   your browser ───►│  RMMZit server           │  console (8443): web interface, API
   (HTTPS 8443)     │  (Linux VM + PostgreSQL)     │  only from your own networks
                    └──────────────▲───────────────┘
                                   │ agents connect outbound (HTTPS 8444)
        ┌──────────────────────────┼──────────────────────────┐
   ┌────┴─────┐              ┌─────┴─────┐              ┌──────┴──────┐
   │ Windows  │              │  Linux    │              │   …         │
   │ agent    │              │  agent    │              │             │
   └──────────┘              └───────────┘              └─────────────┘
```

- **The server** is a Linux machine, usually a small VM (2 vCPU, 2–4 GB RAM, 16 GB disk). It has two ports: the **console** (8443), which accepts connections only from allowed networks, and the **agent endpoint** (8444), which can be opened to the internet for remote sites.
- **Agents** run as a service on every managed computer (Windows MSI, Linux x86-64 and ARM64). They connect to the agent port, pin the server certificate by its fingerprint, and run only commands signed by the server.
- **Small footprint:** in a load test, a server with 2 vCPU and 1 GB RAM handled 1,000 agents with about 200 MB of memory and 3 % CPU; after a restart all of them were back within 8 seconds.

## Installation

| Way | Best for | Needs |
|---|---|---|
| **1. Ready-made VM image** (OVA, qcow2, VHDX) | import, start, sign in, in a few minutes | VMware, Proxmox/KVM or Hyper-V |
| **2. Appliance ISO** | a new VM or a physical server, unattended | internet access during installation |
| **3. Install script** | an existing Debian, Ubuntu, AlmaLinux or Rocky Linux server | root and internet access |
| **4. Packages by hand** | your own PostgreSQL, configuration management | the deb or rpm package of the release |
| **5. Docker** | an existing Docker host, NAS or home lab | Docker with the Compose plugin |

### Downloads

These links always point to the newest release:

| File | What |
|---|---|
| [rmmzit-appliance.ova](https://github.com/Max-Zit/rmmzit/releases/latest/download/rmmzit-appliance.ova) | VM image for VMware ESXi, Workstation, VirtualBox |
| [rmmzit-appliance.qcow2](https://github.com/Max-Zit/rmmzit/releases/latest/download/rmmzit-appliance.qcow2) | VM image for Proxmox VE and KVM |
| [rmmzit-appliance-vhdx.zip](https://github.com/Max-Zit/rmmzit/releases/latest/download/rmmzit-appliance-vhdx.zip) | VM image for Hyper-V (generation 1) |
| [rmmzit-appliance.iso](https://github.com/Max-Zit/rmmzit/releases/latest/download/rmmzit-appliance.iso) | appliance installer ISO |
| [install.sh](https://github.com/Max-Zit/rmmzit/releases/latest/download/install.sh) | install script for an existing Linux server |

The server packages (deb, rpm), the agent installers and the signed manifest are on the [release page](https://github.com/Max-Zit/rmmzit/releases/latest).

### 1. VM image

1. Import the image (VMware: *Deploy a virtual machine from an OVF or OVA file*; Proxmox: `qm importdisk <vmid> rmmzit-appliance.qcow2 local-lvm`; Hyper-V: a generation 1 VM with the VHDX).
2. Start the VM. Its screen shows **the console address and a setup token**.
3. Open `https://<address>:8443`, enter the token and create the first administrator with two-factor sign-in.

The appliance uses DHCP. For a fixed address, the server name or the time zone, sign in on the VM's screen as `rzadmin` (first password `rmmzit`, must be changed) — a setup menu opens.

### 2. Appliance ISO

Boot a VM or server from `rmmzit-appliance.iso`: after 5 seconds it **erases the first disk** and installs Debian, PostgreSQL and RMMZit (10–20 minutes, needs internet access). Then continue as with the VM image.

### 3. Install script

```
curl -fsSL https://github.com/Max-Zit/rmmzit/releases/latest/download/install.sh | sudo sh
```

The script installs PostgreSQL, downloads the newest release, **verifies its signature**, creates the database and starts the service. Run it again to update. Options: `--version X`, `--db postgres://…`, `--no-auto-updates`.

### 4. Packages

```
sudo apt install ./rmmzit-server_X_amd64.deb      # Debian, Ubuntu
sudo dnf install ./rmmzit-server-X-1.x86_64.rpm   # AlmaLinux, Rocky Linux
```

Set `RMMZIT_DB` in `/etc/rmmzit/server.env`, then `systemctl enable --now rmmzit-server`. The setup token is in `/var/lib/rmmzit/setup-token.txt`.

### 5. Docker

The server is also a container image, `ghcr.io/max-zit/rmmzit`, built from the same signed package. Put [docker-compose.yml and .env.example](packaging/docker) into a folder, copy `.env.example` to `.env` and set a database password, then:

```
docker compose up -d
docker compose exec rmmzit rmmzit-server -setup-token
```

Ports: 8443 (console), 8444 (agents). Update with `docker compose pull && docker compose up -d`; the server backs up its database before a new version changes it. The tag `latest` follows official releases, `testing` release candidates.

## Installing agents

In the console, add a customer and a site and create an **enrollment code** on the site. Then:

```
msiexec /i rmmzit-agent-x64.msi /qn ENROLLCODE="RZ1-…"                 # Windows (GPO, Intune, scripts)
sudo ./rmmzit-agent-linux-amd64 install --code "RZ1-…"                  # Linux (systemd)
```

The site page offers the downloads and the exact commands. Agents update themselves to the server's version.

## Updating

*Settings → RMMZit updates* checks GitHub for new releases and installs them (optionally automatically). Only releases signed with the RMMZit release key are installed; the server backs up its database first and rolls back if the new version does not start. The *Testing* update channel offers release candidates for a test console before they become official.

*Settings → Console backup* keeps daily backups of the database, keys and certificates; `rmmzit-server -restore FILE` (or the appliance setup menu) restores them on a new machine.

## Security

- The console and the agent endpoint are separate ports; the console accepts only allowed networks, checked before TLS.
- Agents connect outbound, pin the server certificate and run only commands signed by the server.
- Two-factor sign-in for every account, argon2id passwords, CSRF protection, a strict Content Security Policy, a hash-chained audit log.
- Root actions of the console go through a separate helper with a fixed set of validated requests.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Development

```
go test ./...                       # needs no installed PostgreSQL (embedded)
go build -o bin/rmmzit-server ./cmd/rmmzit-server
bin/rmmzit-server --dev-embedded-db --data-dir .devdata \
  --mgmt-listen 127.0.0.1:18443 --agent-listen 127.0.0.1:18444 --dev-http 127.0.0.1:8095
```

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

RMMZit is free software under the [GNU Affero General Public License v3](LICENSE). The licenses of the libraries it uses are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

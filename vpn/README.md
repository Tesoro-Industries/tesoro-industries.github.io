# Personal WireGuard VPN

A self-hosted WireGuard VPN on one small Ubuntu VPS, used from your phone and
laptop with the official WireGuard apps. Version 1 is for one person and a few
devices.

> **Status:** Phase 1 is done: code, tests and docs. Nothing here has been run
> against a real server yet. See [HANDOFF.md](HANDOFF.md) for exactly what has
> been verified and the Phase 2 checklist.

- Protocol: WireGuard (kernel module + official `wg`/`wg-quick` tools). No custom
  tunnelling or cryptography.
- Default provider: DigitalOcean ([ADR-0002](docs/adr/0002-vps-provider-and-os.md)).
  Everything except `terraform/` is provider-agnostic.
- Decisions and their tradeoffs: [docs/adr/](docs/adr/README.md).

---

## Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
3. [Quickstart (from zero)](#quickstart-from-zero)
4. [Day-to-day operations](#day-to-day-operations)
5. [Other providers](#other-providers)
6. [Threat model](#threat-model)
7. [Troubleshooting](#troubleshooting)
8. [Development](#development)

---

## Architecture

```
  Your laptop (operator)                         VPS (Ubuntu 24.04)
 ┌──────────────────────────┐   SSH (key only)  ┌───────────────────────────────────────┐
 │ make / terraform ────────┼──── DO API ──────▶│ Droplet + Reserved IP + Cloud Firewall│
 │ ansible-playbook ────────┼──────────────────▶│ nftables  fail2ban  unattended-upgr.  │
 │ bin/vpn ── wg genkey     │                   │                                       │
 │    │       (client keys) │   ssh sudo vpnctl │ vpnctl ─▶ /etc/wireguard/peers.json   │
 │    └──────────────────────┼─────────────────▶│    │        (public keys, PSKs)       │
 │ local/  (git-ignored)    │                   │    └─▶ wg0.conf ─▶ wg syncconf (live) │
 │   peers/*.conf  backups/ │                   │ unbound (10.99.0.1:53, tunnel only)   │
 └──────────────────────────┘                   │    └─ DNS-over-TLS ─▶ Quad9           │
                                                └──────────────▲────────────────────────┘
  Phone / laptop (WireGuard app)                               │ UDP 51820 (Reserved IP)
 ┌──────────────────────────┐  WireGuard tunnel                │
 │ 10.99.0.x / fd5b:..::x   ├──────────────────────────────────┘
 │ AllowedIPs 0.0.0.0/0,::/0│  ─▶ NAT (IPv4) + NAT66 (IPv6) ─▶ internet from the Droplet IP
 │ DNS 10.99.0.1            │
 └──────────────────────────┘
```

| Layer | Tool | Responsibility |
|-------|------|----------------|
| Infrastructure | Terraform (`terraform/`) | Droplet, SSH key, Cloud Firewall, Reserved IP; writes `local/ssh_config` and `local/inventory.yml` |
| First boot | cloud-init | Creates the non-root admin user with your key; disables root and password SSH |
| Host config | Ansible (`ansible/`) | Hardening, sysctl, nftables, fail2ban, unattended upgrades, unbound, WireGuard, `vpnctl` |
| Peers | `server/vpnctl` (server), `bin/vpn` (laptop) | Peer registry; live add/revoke; client configs and QR codes; health; backups |

**Network behaviour**

- **Full tunnel by default.** Clients route `0.0.0.0/0` and `::/0` through the VPN.
  Per peer you can instead route only some ranges (`--allowed-ips`) or keep some
  ranges off the VPN, such as your home LAN (`--exclude`).
- **DNS** always goes through the tunnel to unbound on the server, which validates
  DNSSEC and forwards to Quad9 over TLS ([ADR-0006](docs/adr/0006-dns-resolver.md)).
  The resolver's tunnel address is always in `AllowedIPs`, even for split-tunnel
  peers.
- **IPv6** is tunnelled: each peer gets an address in a private ULA prefix and the
  server translates it to its public IPv6 address (NAT66). Setting
  `vpn_ipv6_mode: block` captures and rejects IPv6 instead. Neither mode lets
  IPv6 leak ([ADR-0005](docs/adr/0005-ipv6-handling.md)).
- **Keepalive** is 25 s, so mobile carrier NATs keep the tunnel open.
- **Firewall:** default-deny. Only SSH (22/tcp) and WireGuard (51820/udp) are open
  to the internet, plus the ICMP types IP needs to work. DNS is open only on the
  tunnel. Peers cannot reach each other
  ([ADR-0004](docs/adr/0004-host-firewall.md)).
- **No traffic, DNS or connection logs** ([ADR-0011](docs/adr/0011-logging-and-privacy.md)).

**Where every key lives:** see the table in
[ADR-0007](docs/adr/0007-peer-management.md#where-every-key-lives). In short: the
server key is created on the server and stays there. Client private keys are
created on your laptop, or in the device's app, and never go to the server.
Secrets on the laptop are kept only in `.env` and `local/`, and git ignores both
([ADR-0008](docs/adr/0008-secrets-and-local-state.md)).

---

## Prerequisites

**Accounts and secrets you supply:**

| Item | Where it goes |
|------|---------------|
| DigitalOcean account + API token (read/write) | `.env` → `DIGITALOCEAN_TOKEN` |
| SSH key pair (ed25519 recommended, with a passphrase) | `~/.ssh/`; path in `terraform/terraform.tfvars` |
| age key pair for backups | identity file in your password manager; public `age1…` recipient in `.env` → `VPN_AGE_RECIPIENT` |
| A domain name | **Not needed.** Clients connect to the Reserved IP. |

**Laptop tools** (macOS with Homebrew shown; Linux equivalents are in your
package manager):

```sh
brew install python@3.13 wireguard-tools qrencode age
brew tap hashicorp/tap && brew install hashicorp/tap/terraform
```

`make init` installs Ansible and the linters into `./.venv`, which needs Python
3.13 or newer. `bin/vpn` itself runs on any Python from 3.9 up, including the
macOS system Python. Windows: use WSL2 as the operator machine. The Windows
WireGuard app works as a client either way.

**Devices:** install the official WireGuard app (App Store, Google Play, or
wireguard.com/install for macOS/Windows).

---

## Quickstart (from zero)

All commands run from the `vpn/` directory.

1. **Create an SSH key** (skip if you have one you want to use):
   ```sh
   ssh-keygen -t ed25519 -f ~/.ssh/vpn_ed25519 -C "vpn admin"
   ```

2. **Create a DigitalOcean API token**: in the DigitalOcean console, open API →
   Tokens → Generate New Token, with read and write scope.

3. **Create the backup key** and store the identity file somewhere safe, such as
   your password manager:
   ```sh
   age-keygen -o ~/vpn-backup-identity.txt   # prints "Public key: age1..."
   ```

4. **Fill in local configuration** (both files are git-ignored):
   ```sh
   cp .env.example .env                                   # token + age recipient
   cp terraform/terraform.tfvars.example terraform/terraform.tfvars   # region, key paths
   $EDITOR .env terraform/terraform.tfvars
   ```

5. **Initialise:** this creates `local/` (mode 0700) and the `.venv`, installs the
   Ansible collections and runs `terraform init`.
   ```sh
   make init
   git add terraform/.terraform.lock.hcl && git commit -m "Pin Terraform provider versions"
   ```

6. **Create the server and configure it:**
   ```sh
   make plan     # review: 1 droplet, 1 ssh key, 1 firewall, 1 reserved IP (+assignment), 2 local files
   make up       # = make infra, make wait-ssh, make configure
   ```
   The first SSH connection trusts the new server's host key on first use and
   stores it in `local/known_hosts` (see [Threat model](#threat-model)).
   `make configure` finishes by running the health check and fails if anything
   is wrong.

7. **Check idempotency.** A second run must report `changed=0`:
   ```sh
   make configure
   ```

8. **Add your phone.** A QR code appears in the terminal. In the app, tap
   **+ → Create from QR code** and scan it.
   ```sh
   bin/vpn peer add phone
   ```

9. **Add your laptop.** Import `local/peers/laptop.conf` in the WireGuard app with
   *Import tunnel(s) from file*.
   ```sh
   bin/vpn peer add laptop --no-qr
   ```
   Alternatively, create an empty tunnel in the macOS/Windows app (the app
   generates the private key) and register only its public key:
   `bin/vpn peer add laptop --public-key <key shown in app>`. The command prints
   the rest of the config to paste into the app.

10. **Leak-test each device** with [docs/leak-testing.md](docs/leak-testing.md).

11. **Back up** the server key and peer list:
    ```sh
    make backup        # → local/backups/vpn-<timestamp>.tar.age
    ```

---

## Day-to-day operations

### Peers

```sh
bin/vpn peer add NAME                    # full tunnel, QR code, config saved to local/peers/
bin/vpn peer add NAME --exclude 192.168.1.0/24          # full tunnel except your home LAN
bin/vpn peer add NAME --allowed-ips 10.20.0.0/16        # split tunnel: only this range
bin/vpn peer add NAME --keepalive 0                     # desktop on a stable network
bin/vpn peer add NAME --no-save                         # show the QR, keep no copy
bin/vpn peer list                        # names, addresses, latest handshake
bin/vpn peer qr NAME                     # show a saved config's QR code again
bin/vpn peer revoke NAME                 # immediate; no restart or rebuild
```

Revocation removes the peer from the running interface with `wg syncconf`, which
drops its session immediately. Other peers are not disturbed. Then delete the
tunnel in that device's app. Run `make backup` after changing peers.

Peer names are 1–32 characters of `a-z`, `0-9` and `-`.

### Health check

```sh
make health          # = bin/vpn health = ssh vpn sudo vpnctl health
```

Checks: config and key permissions, interface up, listen port, **registered
peers = live peers** (catches an incomplete revoke), IPv4/IPv6 forwarding,
services (WireGuard, nftables, unbound, fail2ban, sshd), firewall tables loaded,
unattended upgrades enabled, effective sshd settings, DNS resolution through the
tunnel resolver, DNSSEC validation, and a pending reboot. It exits non-zero on
any FAIL.

### Changing settings

Edit `ansible/group_vars/all.yml` (or put per-host overrides in
`local/inventory.yml`), then run `make check` to preview and `make configure` to
apply. To change infrastructure, edit `terraform/terraform.tfvars`, then run
`make plan` and `make infra`.

### Backup and restore

```sh
make backup                                               # encrypt to VPN_AGE_RECIPIENT
bin/vpn restore local/backups/vpn-<ts>.tar.age --identity ~/vpn-backup-identity.txt
```

The backup contains the server private key, the peer registry and the server
parameters. It is streamed over SSH and encrypted on your laptop, so plaintext
never touches either disk. Restore validates the archive strictly, installs the
files atomically and applies them live
([ADR-0009](docs/adr/0009-backup-and-restore.md)).

**Rebuild a dead server:** run
`terraform -chdir=terraform apply -replace=digitalocean_droplet.vpn`, then
`make wait-ssh configure`, then `bin/vpn restore …`. The Reserved IP stays the same, so existing client configs
keep working. (The new Droplet has a new SSH address, which Terraform writes into
`local/ssh_config`.)
*If the server was compromised, do not restore. Rotate everything instead (next
section).*

### Rotating the server key

This is not automated in v1. It invalidates every client config, so all peers
must be re-added:

```sh
ssh -F local/ssh_config vpn 'sudo rm /etc/wireguard/server.key /etc/wireguard/peers.json'
make configure                       # generates a new server key
bin/vpn peer add phone --force       # repeat for each device, re-import in the app
```

### Teardown

```sh
make backup     # optional: keep the server identity
make destroy    # asks for confirmation; destroys Droplet, firewall, Reserved IP, SSH key
```

`local/peers/`, `local/backups/` and the Terraform state are kept. Delete
`local/` yourself to remove every trace, and delete the API token in the
DigitalOcean console.

---

## Other providers

Only `terraform/` is DigitalOcean-specific. For any other provider:

1. Create an Ubuntu 24.04 VPS with IPv6. Paste
   `terraform/templates/cloud-init.yaml.tftpl` into the provider's user-data
   field, replacing `${admin_user}` and `${jsonencode(ssh_public_key)}` with your
   values. Without cloud-init, create a sudo user with your key by hand.
2. Open 22/tcp and 51820/udp in the provider firewall, if it has one.
3. Write `local/ssh_config` and `local/inventory.yml` by hand, following the
   formats in `terraform/templates/ssh_config.tftpl` and
   `terraform/templates/inventory.yml.tftpl`.
4. Run `make configure`, then follow the Quickstart from step 7.

If the host has no IPv6, set `vpn_ipv6_mode: block` in the inventory.

---

## Threat model

**What this protects**

| Threat | How |
|--------|-----|
| Untrusted local networks (cafés, hotels, airports) reading or tampering with your traffic | All traffic is encrypted to the VPS (WireGuard: Curve25519, ChaCha20-Poly1305, plus a per-peer preshared key as a hedge against future quantum attacks) |
| Your ISP or local network seeing which sites you visit (DNS and IP metadata) | Full tunnel, DNS forced through the tunnel, DoT from the VPS to Quad9 |
| IPv6 or DNS leaks around the tunnel | `::/0` always routed; tunnel resolver address always in AllowedIPs; leak tests |
| Websites learning your home or mobile IP address | They see the Droplet's IP |
| Internet scanning and SSH brute force against the server | Default-deny firewall at two layers, key-only SSH, no root login, fail2ban |
| Unpatched server software | Daily unattended security upgrades with automatic reboots |
| Lost or stolen device | `bin/vpn peer revoke` takes effect immediately |
| Server compromise exposing client private keys | Client private keys are never on the server |
| Secrets leaking through this (likely public) repository | Nothing secret is committed; `.gitignore`, gitleaks and a hygiene test enforce it |

**What this does NOT protect against**

- **The VPS provider.** DigitalOcean controls the hypervisor and can read the
  server's memory and disk, including the server private key, and can watch
  traffic leaving the Droplet. You are moving trust from your ISP to your
  provider.
- **Anonymity.** The exit IP is a static address rented in your name and paid
  with your card. It identifies you to anyone who can ask DigitalOcean. This is
  a privacy tool for untrusted networks, not Tor.
- **Traffic analysis.** Timing and volume of encrypted traffic are visible to
  your local network and to the VPS's upstream. The exit side is plaintext
  unless the site uses HTTPS.
- **Quad9.** Quad9 sees your DNS queries, from the VPS's address. You can switch
  upstreams in `vpn_dns_upstreams`.
- **Compromise of your laptop.** The laptop holds the SSH key (which gives root
  on the server through passwordless sudo), the API token and the peer configs.
  Protect the SSH key with a passphrase or a hardware key.
- **Compromise of a device.** Whoever has a device's config can use the VPN
  until you revoke it.
- **Malware, tracking cookies and browser fingerprinting.** These are unaffected
  by any VPN.
- **Platform leaks outside WireGuard's control.** For example, iOS may send some
  Apple traffic outside VPNs, and apps can bypass a split tunnel. See the
  kill-switch notes in [leak testing](docs/leak-testing.md#5-tunnel-drop-behaviour-kill-switch).
- **Availability.** One VPS in one region is a single point of failure. When it
  is down, clients have no VPN (or no connectivity, if they fail closed).

**Accepted risks (v1)**

- **Trust on first use for the SSH host key.** The first connection to a
  minutes-old server is trusted without out-of-band verification. A
  man-in-the-middle at exactly that moment is very unlikely; after that,
  `local/known_hosts` pins the key.
- **Passwordless sudo for the admin user** ([ADR-0012](docs/adr/0012-host-hardening.md)).
- **SSH is reachable from anywhere** by default. Narrow `ssh_allowed_cidrs` if
  your home or office ranges are stable.
- **Backups are manual** ([ADR-0009](docs/adr/0009-backup-and-restore.md)).

---

## Troubleshooting

| Symptom | Likely cause → fix |
|---------|--------------------|
| `make infra`: 401 Unauthorized | `DIGITALOCEAN_TOKEN` missing or read-only → check `.env` (no quotes around values). |
| `make wait-ssh` never succeeds | Droplet still booting (wait), or the wrong key → `ssh -v -F local/ssh_config vpn`; check the `IdentityFile` in `local/ssh_config`. |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | Possible after a rebuild if the provider reuses an old IP for the new Droplet → `ssh-keygen -f local/known_hosts -R <droplet ip>`. Investigate if you did *not* rebuild. |
| Ansible: "Unsupported OS" | Image is not Ubuntu 24.04 → use `ubuntu-24-04-x64`. |
| Ansible: "has no global IPv6 address" | IPv6 disabled at the provider → enable it, or set `vpn_ipv6_mode: block`. |
| Ansible fails in `ssh_hardening` | It refuses to lock you out or found password/root login still effective. Read the message; nothing has been reloaded if validation failed. |
| `vpn peer add`: "sudo: a password is required" | Admin user lacks passwordless sudo → re-run `make configure` (the base role installs it). |
| Phone connects but nothing loads | Check: (1) `bin/vpn peer list` shows a recent handshake? If **never**, UDP 51820 is blocked on your network or the provider firewall; try another network. (2) A handshake but no traffic → `make health` (forwarding, firewall tables, peers in sync). |
| Websites load by IP but not by name | DNS → `make health` (`unbound service`, `dns resolves`). On the device, check DNS is `10.99.0.1` (leak tests §3). |
| Some sites hang (large pages, uploads) | MTU/PMTU black hole. The server clamps TCP MSS; if it persists, add `MTU = 1280` to the client's `[Interface]` and re-import. |
| `health`: `peers in sync` FAIL | Live peers differ from the registry (for example an interrupted revoke) → `ssh -F local/ssh_config vpn sudo vpnctl apply`. |
| `health`: `dnssec validation` WARN | Upstream issue or validation off; check `/etc/unbound/unbound.conf.d/`. Not fatal. |
| `health`: `reboot` WARN | A kernel update is waiting; it reboots at 04:30 UTC. Reboot now with `make ssh` → `sudo reboot`. |
| Tunnel drops after the phone sleeps | Normal; it reconnects on next use. For always-on, enable On-Demand (iOS/macOS) or Always-on VPN (Android). |
| Locked out of SSH | There is no password fallback by design → rebuild and restore (see Backup and restore). |
| Debugging WireGuard live | `make ssh`, then `sudo wg show` (handshakes, transfer) and `sudo nft list ruleset`. Nothing is logged, so debug while the problem is happening. |

---

## Development

```sh
make lint   # shellcheck, ruff, yamllint, ansible-lint, terraform fmt/validate, tflint, gitleaks
make test   # pytest: vpnctl, bin/vpn (incl. end-to-end), template rendering, repo hygiene
sudo make test   # additionally runs the real-packet WireGuard lab in network namespaces (Linux)
```

| Path | Purpose |
|------|---------|
| `bin/vpn` | Operator CLI (laptop), Python ≥ 3.9, stdlib only |
| `server/vpnctl.py` | Server CLI, installed to `/usr/local/sbin/vpnctl` |
| `terraform/` | DigitalOcean resources + templates for cloud-init and local files |
| `ansible/` | `site.yml` + one role per concern; shared vars in `group_vars/all.yml` |
| `tests/` | pytest suite (see [ADR-0010](docs/adr/0010-testing-and-linting.md)) |
| `docs/adr/` | Architecture decision records |
| `local/` | **Git-ignored** state and secrets |

CI (`.github/workflows/vpn-ci.yml` at the repository root) runs strict lint and
the full test suite on every change under `vpn/`.

Growing beyond one user (not built): the `vpnctl` registry and its JSON contract
are versioned (`"schema": 1`) so they can gain owner fields. Peer limits come
from the tunnel subnet (`/24` = 253 peers). The main gaps for multi-user are
per-user authorisation for peer management (today it is SSH plus sudo) and
moving the registry off a single host.

# ADR-0007: Peer management tooling and key placement

- Status: Accepted
- Date: 2026-11-09

## Context

We need to add, list and revoke peers; produce a client config and a QR code; and
make revocation take effect immediately without rebuilding the server. We also need
to decide where every private key is generated and stored.

## Options considered

1. **Web UI (e.g. wg-easy).** Convenient, but adds a container runtime and an
   authenticated web service exposed on the server — more attack surface than the
   VPN itself.
2. **Ansible-managed peer list.** Peers in a vars file, re-run the playbook to
   change them. Slow (whole playbook per change) and puts the peer list — and
   therefore keys or configs — in the repository or near it.
3. **Server-side script that generates everything.** Simple, but every client
   private key is generated on, and passes through, the server.
4. **Two small cooperating CLIs:** a laptop CLI that generates client keys and
   renders configs/QR codes, and a server CLI that owns the peer registry and
   applies changes live.

## Decision

Option 4. Both tools are single-file Python 3 programs using only the standard
library and the official `wg` / `wg-quick` binaries for all cryptography.

**`server/vpnctl`** (installed to `/usr/local/sbin/vpnctl` by Ansible, run via sudo):

- Source of truth for peers: `/etc/wireguard/peers.json` (0600, schema-versioned,
  written atomically under an exclusive lock).
- Renders `/etc/wireguard/wg0.conf` from the registry plus Ansible-owned server
  parameters (`/etc/wireguard/vpnctl.json`), then applies it with
  `wg syncconf wg0 <(wg-quick strip wg0)` — the documented way to change peers
  without disturbing other sessions. **Revocation is therefore immediate and needs
  no restart or rebuild.**
- Allocates tunnel addresses (lowest free host in the IPv4 and IPv6 subnets).
- Never sees a client private key.
- Also provides `health`, `backup` and `restore` (ADR-0009).

**`bin/vpn`** (runs on the operator's laptop):

- `vpn peer add NAME`: runs `wg genkey`/`wg pubkey`/`wg genpsk` locally, sends the
  *public* key over SSH (preshared key via stdin, never argv), receives the assigned
  addresses and server parameters as JSON, renders the client config to
  `local/peers/NAME.conf` (0600) and prints a terminal QR code (`qrencode`).
- `--public-key KEY` registers a key generated elsewhere (e.g. created in the
  macOS/Windows WireGuard app), in which case no private key touches the laptop.
- `--allowed-ips` / `--exclude` produce a per-peer split tunnel; the server's
  tunnel DNS addresses are always included.
- `vpn peer list`, `vpn peer revoke NAME`, `vpn peer qr NAME`, `vpn health`,
  `vpn backup`, `vpn restore`.

A WireGuard **preshared key** is generated per peer. It adds a symmetric layer to
the handshake as a hedge against future quantum attacks on Curve25519, as
recommended by the WireGuard whitepaper; cost is negligible.

### Where every key lives

| Key | Generated on | Stored at | Leaves its home? |
|-----|--------------|-----------|------------------|
| Server private key | Server (Ansible, `wg genkey`, first run only) | `/etc/wireguard/server.key` and inside `wg0.conf` (0600, root) | Only inside the age-encrypted backup |
| Peer private key (default flow) | Laptop (`wg genkey`) | `local/peers/NAME.conf` (0600) → imported into the device app via QR/file | Shown once as QR; never sent to the server |
| Peer private key (`--public-key` flow) | The device's WireGuard app | The device only | Never |
| Peer preshared key | Laptop (`wg genpsk`) | `local/peers/NAME.conf` and `/etc/wireguard/peers.json` | Sent to the server once over SSH stdin |
| Your SSH key | Laptop (`ssh-keygen`) | `~/.ssh/` | Public half to DigitalOcean and the server |
| DigitalOcean API token | DigitalOcean console | `.env` (git-ignored) | Used by Terraform only |
| age backup identity | Laptop (`age-keygen`) | Your password manager; recipient (public) in `.env` | Never |

## Tradeoffs

- (+) Server compromise reveals public keys and PSKs, never client private keys.
- (+) Changes are instant; no playbook run per peer.
- (−) Two small programs instead of one; they communicate over a small, versioned
  JSON contract (`"schema": 1`) that is covered by tests.
- (−) For phones the private key is generated on the laptop and transferred by QR.
  The official iOS/Android apps can only import a complete config by QR, so this is
  the practical minimum. Delete `local/peers/NAME.conf` afterwards if you do not
  want a copy (`vpn peer add --no-save`).
- (−) The laptop CLI needs Python ≥ 3.9, `wg` (wireguard-tools) and `qrencode`.

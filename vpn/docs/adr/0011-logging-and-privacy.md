# ADR-0011: Logging and privacy policy

- Status: Accepted
- Date: 2026-11-09

## Context

Requirement: no logging of user traffic or connection history beyond what is needed
to debug the service itself.

## Decision

| Component | What is recorded | Setting |
|-----------|------------------|---------|
| WireGuard (kernel) | Nothing. Only in-memory state: latest handshake time and byte counters per peer, lost on reboot. | Dynamic debug left off |
| nftables | Nothing. No `log` rules. Conntrack keeps in-memory flow state required for NAT, never written to disk. | — |
| unbound | Startup/errors only. No queries, no replies. | `verbosity: 0`, `log-queries: no`, `log-replies: no`, `log-servfail: no` |
| sshd / fail2ban | Admin login attempts and bans (source IPs of SSH clients — needed to debug and to ban). Not VPN traffic. | fail2ban `dbpurgeage = 1d` |
| journald | System logs above, bounded. | `MaxRetentionSec=7day`, `SystemMaxUse=200M` |
| `vpnctl` | Peer name, public key, PSK, tunnel addresses, creation date. No connection history. | — |
| Provider monitoring agent | Disabled. | Terraform `monitoring = false` |

`vpnctl list` shows each peer's *latest handshake* by reading live kernel state at
the moment you run it; it is not stored.

## Tradeoffs

- (+) No traffic or DNS history exists on the server to be stolen or subpoenaed.
- (−) Debugging "why did my phone disconnect at 3 pm" is not possible after the
  fact; you debug live with `wg show` and `vpn health`.
- Out of scope: the VPS provider and upstream networks can observe traffic
  metadata (volume, timing, destinations of the VPS's egress). See threat model.

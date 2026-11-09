# ADR-0004: Host firewall and NAT

- Status: Accepted
- Date: 2026-11-09

## Context

The host must be default-deny inbound, allowing only SSH and the WireGuard UDP
port from the internet. It must also forward and NAT traffic from the tunnel to the
internet, block forwarding for everything else, and expose the DNS resolver only to
tunnel clients. fail2ban must be able to add its own bans.

## Options considered

1. **ufw.** Friendly for simple input rules, but forwarding and NAT require editing
   `/etc/ufw/before.rules` in iptables syntax — two languages in one config.
2. **wg-quick `PostUp`/`PostDown` iptables hooks.** Common in tutorials; rules only
   exist while the interface is up, and forward/NAT policy becomes scattered.
3. **nftables, one declarative ruleset** loaded by the stock `nftables.service`.
4. **firewalld.** Not the Ubuntu default; zone model adds indirection.

## Decision

Option 3, plus the provider Cloud Firewall as an outer layer (ADR-0002).

- `/etc/nftables.conf` is rendered by Ansible from one template and validated with
  `nft -c` before it is installed.
- It manages **only its own tables** (`inet vpn_filter`, `inet vpn_nat`) using the
  declare-then-delete idiom instead of `flush ruleset`, so reloading it never wipes
  fail2ban's table.
- `input` policy **drop**. Accepted: established/related, loopback, SSH (tcp/22),
  WireGuard (udp/51820), DNS (53) **only on the WireGuard interface**, and the ICMP /
  ICMPv6 types required for IPv4/IPv6 to function (path-MTU discovery and IPv6
  neighbour discovery; blocking these silently breaks connectivity — this is the one
  intentional addition beyond "SSH and WireGuard only").
- `forward` policy **drop**. Accepted: established/related, and new flows from the
  WireGuard interface to the WAN interface. Peer-to-peer traffic between VPN clients
  is dropped (v1 is a personal egress VPN, not a LAN).
- NAT: IPv4 masquerade of the tunnel subnet out of the WAN interface; IPv6 per
  ADR-0005.
- No `log` statements: nothing about user traffic is written anywhere (ADR-0011).
- `ufw` is removed so there is exactly one host firewall.

## Tradeoffs

- (+) The entire network policy is one readable, reviewable file.
- (+) Rules exist independently of the WireGuard interface state, so there is never
  a window where the tunnel is up but unfiltered.
- (−) nftables syntax is less familiar than ufw to some operators.
- (−) The ruleset template can only be syntax-checked with `nft -c` on a host with
  netlink access; in CI it is rendered and structurally asserted (ADR-0010).

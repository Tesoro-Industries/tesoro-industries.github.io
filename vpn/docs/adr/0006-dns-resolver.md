# ADR-0006: DNS resolution and leak protection

- Status: Accepted
- Date: 2026-11-09

## Context

DNS queries must go through the tunnel, in both full- and split-tunnel modes, and
must not end up in plaintext logs of the VPS provider's network. We also need to
pick and justify an upstream resolver.

## Options considered

1. **Push a public resolver directly** (e.g. `DNS = 9.9.9.9`). Works in full-tunnel
   mode, but a split-tunnel peer would send DNS outside the tunnel unless the
   resolver IP is also in `AllowedIPs`; plaintext from the VPS onward.
2. **Run a full recursive resolver on the server** (unbound, no forwarder). No
   third-party resolver sees the query stream; but every query to authoritative
   servers leaves the VPS in plaintext, tied to the VPS IP.
3. **Run unbound on the server, listening only on the tunnel, forwarding over
   DNS-over-TLS to a privacy-focused public resolver, with DNSSEC validation.**

Upstream candidates: Quad9 (non-profit, Swiss jurisdiction, states it does not log
client IPs, threat-blocking, DoT on 853), Cloudflare 1.1.1.1 (fast, audited
no-logging commitments, US company), Google 8.8.8.8 (logs temporarily, ad company),
Mullvad DNS (good privacy, smaller anycast footprint).

## Decision

Option 3 with **Quad9** (`9.9.9.9`, `149.112.112.112`, `2620:fe::fe`,
`2620:fe::9`, TLS name `dns.quad9.net`) as the default upstream.

- Clients receive `DNS = <server tunnel IPv4>, <server tunnel IPv6>`.
- Those two addresses are **always** added to a peer's `AllowedIPs`, including in
  split-tunnel mode, so DNS cannot bypass the tunnel.
- unbound binds only to the tunnel addresses (`ip-freebind` lets it start before
  `wg0` exists), `access-control` allows only tunnel subnets, and nftables only
  accepts port 53 on the WireGuard interface. It is not an open resolver.
- unbound runs with `verbosity: 0`, no query or reply logging (ADR-0011), DNSSEC
  validation, QNAME minimisation and `hide-identity`/`hide-version`.
- Forwarding uses DoT with certificate verification against the system CA bundle,
  so the VPS provider's network sees only TLS to Quad9.
- The upstream list is a variable; switching to Cloudflare or Mullvad is a
  one-line change.

Why Quad9: it combines a public no-client-IP-logging policy, non-profit governance
and a jurisdiction with strong privacy law, and adds malware-domain blocking that
is useful on a phone. Note that because queries are forwarded *from the VPS*, Quad9
sees the VPS address, never your device's real address.

## Tradeoffs

- (+) DNS always traverses the tunnel; upstream sees TLS from the VPS only.
- (−) You trust Quad9 with the query stream (but not with your identity/IP).
- (−) Quad9's threat-blocking occasionally blocks a legitimate domain; switch the
  upstream if that is a problem.
- (−) One more daemon on the server.

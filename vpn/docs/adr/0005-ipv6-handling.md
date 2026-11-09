# ADR-0005: IPv6 handling

- Status: Accepted
- Date: 2026-11-09

## Context

A full-tunnel VPN that only routes IPv4 leaks: the device keeps using its native
IPv6 connectivity for every dual-stack site, exposing the real network's address.
This is the most common VPN leak. We must either carry IPv6 through the tunnel or
capture and block it — never ignore it.

DigitalOcean gives a Droplet a single public IPv6 address (from a small range), not
a routed prefix we could delegate to clients.

## Options considered

1. **Ignore IPv6** — rejected; it leaks.
2. **Capture and block:** clients route `::/0` into the tunnel; the server rejects
   it with ICMPv6 "administratively prohibited" so apps fall back to IPv4 quickly.
   No leak, but IPv6-only destinations become unreachable.
3. **Tunnel with public addresses:** needs a routed prefix (or NDP proxying of a
   tiny range). Not available on the default provider; fragile.
4. **Tunnel with a ULA prefix + NAT66 (masquerade).** Clients get an address in a
   private `fd00::/8` prefix; the server masquerades to its public IPv6 address,
   exactly as IPv4 is masqueraded.

## Decision

**Option 4 by default (`vpn_ipv6_mode: tunnel`), with option 2 available as
`vpn_ipv6_mode: block`.**

In *both* modes every peer gets an IPv6 tunnel address and the client config always
includes `::/0` in full-tunnel mode, so the operating system sends IPv6 into the
tunnel instead of out of the local network. The mode only changes what the server
does with it (masquerade and forward vs. reject). `block` exists for providers or
hosts without working IPv6; Ansible refuses `tunnel` mode if the host has no
global IPv6 address.

The default ULA prefix is `fd5b:7a13:c0e2:9f41::/64` (randomly generated for this
project as RFC 4193 requires, not a well-known value). Override it in
`ansible/group_vars/all.yml` if it collides with another network you use.

## Tradeoffs

- (+) No IPv6 leak in either mode; IPv6-only sites work in the default mode.
- (−) NAT66 is frowned upon by IPv6 purists. For a single-user egress VPN its
  downsides (no end-to-end addressability) are exactly the property we want.
- (−) Clients prefer IPv4 over ULA-sourced IPv6 per RFC 6724 address selection, so
  in practice most traffic still uses IPv4 through the tunnel. This is harmless.
- (−) Split-tunnel peers only route the IPv6 ranges they list; that is the point of
  split tunnel, and is documented in the leak-test guide.

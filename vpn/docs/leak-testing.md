# Leak testing

Run these from **each device** after connecting, and again after any change to
the firewall, DNS or IPv6 settings. Record results in the table at the bottom.

## 0. Know what "correct" looks like

On your laptop:

```sh
terraform -chdir=terraform output exit_ipv4   # websites should see this IPv4
terraform -chdir=terraform output exit_ipv6   # ...and this IPv6 (tunnel mode)
terraform -chdir=terraform output endpoint_ip # clients connect here (NOT the exit IP)
```

The endpoint (Reserved IP) and the exit address (the Droplet's own IP) are
**different** on DigitalOcean: inbound traffic to a Reserved IP is delivered to
the Droplet, but outbound traffic leaves from the Droplet's own public address.
Seeing the exit IP — not the endpoint IP — is correct.

Write down your real (non-VPN) IPv4 and IPv6 first by running the tests below
with the tunnel **off**.

## 1. IPv4 exit address

| Platform | Test | Pass if |
|----------|------|---------|
| macOS / Linux | `curl -4 -s https://icanhazip.com` | equals `exit_ipv4` |
| Windows | `curl.exe -4 -s https://icanhazip.com` | equals `exit_ipv4` |
| iOS / Android | open https://icanhazip.com in the browser | equals `exit_ipv4` |

## 2. IPv6 (the most common leak)

| Platform | Test | Pass if (`tunnel` mode) | Pass if (`block` mode) |
|----------|------|------------------------|------------------------|
| macOS / Linux | `curl -6 -s --max-time 5 https://icanhazip.com` | equals `exit_ipv6` | fails/times out — never shows your real IPv6 |
| Windows | `curl.exe -6 -s --max-time 5 https://icanhazip.com` | same | same |
| Any browser | https://test-ipv6.com | IPv6 address = `exit_ipv6` | "No IPv6 address detected" |

**FAIL** in either mode: the page shows your real ISP IPv6 address. Check that the
peer config's `AllowedIPs` contains `::/0` (full tunnel) and that the device has
no IPv6-specific VPN bypass setting.

## 3. DNS

DNS must go to the tunnel resolver (unbound on the server), which forwards to
Quad9 over TLS. Your ISP's resolver must never appear.

| Test | Pass if |
|------|---------|
| Browser: https://on.quad9.net | "YES, you ARE using Quad9" |
| Browser: https://www.dnsleaktest.com → *Extended test* | only Quad9 / WoodyNet servers; **no** ISP servers |
| `dig +short whoami.akamai.net` (macOS/Linux) | an address that is **not** your ISP's resolver (it will be a Quad9 egress address) |
| `dig +short @10.99.0.1 example.com` | returns an answer (resolver reachable through the tunnel) |
| macOS: `scutil --dns \| grep nameserver` | first resolvers are `10.99.0.1` / `fd5b:7a13:c0e2:9f41::1` |
| Windows: `Get-DnsClientServerAddress` (PowerShell) | the WireGuard adapter lists `10.99.0.1` |
| `dig +short dnssec-failed.org` | **no** answer (DNSSEC validation rejects the bogus domain) |

Adjust `10.99.0.1` / the IPv6 prefix if you changed `vpn_ipv4_network` /
`vpn_ipv6_network`.

## 4. WebRTC

Open https://browserleaks.com/webrtc. Any **public** address shown must be the
exit address. Local/private addresses (`10.99.0.x`, `192.168.x.x`, mDNS
`*.local` names) are expected and not a leak of your public identity.

## 5. Tunnel drop behaviour ("kill switch")

WireGuard itself has no kill switch; the OS does.

| Platform | How to make traffic fail closed |
|----------|---------------------------------|
| Windows | Automatic when the tunnel's `AllowedIPs` is exactly `0.0.0.0/0, ::/0` ("Block untunneled traffic" is ticked in the editor). Using `--exclude` disables it. |
| Android | Settings → Network → VPN → WireGuard → *Always-on VPN* + *Block connections without VPN* |
| iOS | Edit tunnel → *On-Demand Activation* (Wi-Fi + cellular). iOS does not offer a hard kill switch and may send some Apple system traffic outside any VPN; this is a platform limitation. |
| macOS | Edit tunnel → *On-Demand*. The macOS app has no hard kill switch. |

Test: with the tunnel on, block UDP 51820 on your router or switch networks;
traffic should stop (fail closed) or, on iOS/macOS, the tunnel should come back
on its own within about 25 s (`PersistentKeepalive`).

## 6. Split-tunnel peers

For peers created with `--allowed-ips` or `--exclude`:

- `curl -4 https://icanhazip.com` shows your **real** IP (expected: the internet is not in AllowedIPs) for `--allowed-ips` peers, and the exit IP for `--exclude` peers.
- Hosts in the listed ranges are reached through the tunnel (`traceroute` shows `10.99.0.1` as the first hop).
- DNS **still** goes through the tunnel: `dig +short whoami.akamai.net` is not your ISP. (The tunnel resolver's address is always in AllowedIPs.) Some OSes only use a VPN's DNS for all queries when it carries the default route; if test 3 fails on a split-tunnel peer, that is the OS's behaviour, not a server problem — record it.

## 7. Server side

```sh
bin/vpn peer list     # latest handshake per peer (live kernel state, not stored)
bin/vpn health        # every check should PASS
```

## Results (fill in during Phase 2)

| Date | Device / OS | App version | Mode | IPv4 | IPv6 | DNS | WebRTC | Drop test | Notes |
|------|-------------|-------------|------|------|------|-----|--------|-----------|-------|
|      |             |             |      |      |      |     |        |           |       |

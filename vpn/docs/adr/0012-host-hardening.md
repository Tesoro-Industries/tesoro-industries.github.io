# ADR-0012: Host hardening baseline

- Status: Accepted
- Date: 2026-11-09

## Context

Required: key-only SSH, no root login, non-default user, default-deny firewall
(ADR-0004), unattended security upgrades, fail2ban or equivalent, and correct
kernel settings for forwarding.

## Decisions

**SSH**
- Admin user `wgadmin` (configurable; never `root` or `ubuntu`), created by
  cloud-init with your public key, re-asserted by Ansible.
- Drop-in `/etc/ssh/sshd_config.d/00-vpn-hardening.conf`. The `00-` prefix matters:
  sshd uses the *first* value it reads, and provider images ship
  `50-cloud-init.conf`, which may set `PasswordAuthentication yes`.
- `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `AuthenticationMethods publickey`, `AllowUsers wgadmin`, `MaxAuthTries 3`,
  `LoginGraceTime 30`, no X11/agent/TCP forwarding.
- Ansible verifies the *effective* configuration with `sshd -T` and fails the run if
  root or password login is still possible.
- **Port 22 is kept.** A non-standard port only reduces log noise; it complicates
  the provider firewall, Ubuntu's socket-activated sshd and every client. Key-only
  auth plus fail2ban is the actual control.
- **Passwordless sudo for the admin user.** Required for non-interactive Ansible and
  `vpn` commands. Consequence: compromise of your SSH private key is root on the
  server. Mitigation: protect the key with a passphrase / hardware key (see README).

**Unattended upgrades**
- `unattended-upgrades` enabled for the `-security` pocket (Ubuntu default origins).
- `Automatic-Reboot "true"` at **04:30 UTC** (configurable), only when a reboot is
  required. A kernel fix that is installed but not booted protects nothing; a ~1
  minute VPN outage in the middle of the night is the cost. Clients reconnect
  automatically.

**fail2ban**
- `sshd` jail, `backend = systemd`, `banaction = nftables-multiport`, 5 failures in
  10 minutes → 1 hour ban, incremental for repeat offenders. With key-only auth
  this is noise reduction more than protection.

**Kernel / sysctl** (`/etc/sysctl.d/90-vpn.conf`)
- `net.ipv4.ip_forward = 1`, `net.ipv6.conf.all.forwarding = 1` (required to route
  tunnel traffic).
- `net.ipv6.conf.<wan>.accept_ra = 2` so enabling IPv6 forwarding does not make the
  WAN interface drop router advertisements on providers that use SLAAC.
- No ICMP redirects accepted or sent, no source routing, `rp_filter = 2` (loose:
  strict reverse-path filtering can drop legitimate asymmetric replies on some
  provider networks), TCP SYN cookies on, `kernel.kptr_restrict = 2`,
  `kernel.dmesg_restrict = 1`.

**Misc**
- Provider monitoring agent disabled (ADR-0011).
- Time sync via the default `systemd-timesyncd` (WireGuard handshakes and TLS for
  DoT need a sane clock).

## Tradeoffs

- (−) Passwordless sudo trades defence-in-depth for automation; documented in the
  threat model.
- (−) Automatic reboots cause a brief nightly outage on days a kernel update lands.
- (−) No SSH lockout recovery path except rebuild + restore (by design: there is no
  password to fall back on). The rebuild path is fully automated.

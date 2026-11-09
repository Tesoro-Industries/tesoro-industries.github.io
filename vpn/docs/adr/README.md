# Architecture decision records

| ADR | Decision |
|-----|----------|
| [0001](0001-repo-layout-and-adrs.md) | Project lives in `vpn/` of the existing repository; ADR process |
| [0002](0002-vps-provider-and-os.md) | DigitalOcean + Reserved IP + Cloud Firewall; Ubuntu 24.04 LTS |
| [0003](0003-provisioning-and-config-management.md) | Terraform (infra) + minimal cloud-init (bootstrap) + Ansible (host) |
| [0004](0004-host-firewall.md) | nftables, own tables only, default-deny input and forward |
| [0005](0005-ipv6-handling.md) | IPv6 tunnelled via ULA + NAT66; `block` mode available |
| [0006](0006-dns-resolver.md) | unbound on the tunnel, DoT to Quad9, DNSSEC |
| [0007](0007-peer-management.md) | `bin/vpn` (laptop) + `vpnctl` (server); key placement table |
| [0008](0008-secrets-and-local-state.md) | Nothing secret in git; everything in `local/` and `.env` |
| [0009](0009-backup-and-restore.md) | Streamed, age-encrypted backups of server key + peer registry |
| [0010](0010-testing-and-linting.md) | Linters + unprivileged pytest + on-host health check |
| [0011](0011-logging-and-privacy.md) | No traffic/DNS/connection logs; bounded journald |
| [0012](0012-host-hardening.md) | SSH, sudo, unattended upgrades, fail2ban, sysctl |

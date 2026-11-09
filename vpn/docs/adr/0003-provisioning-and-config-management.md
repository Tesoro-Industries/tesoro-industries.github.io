# ADR-0003: Provisioning and configuration management

- Status: Accepted
- Date: 2026-11-09

## Context

We need to create a VPS, harden it, install and configure WireGuard plus a DNS
resolver, and be able to re-run everything safely. Requirements: idempotent,
reviewable, lintable, a teardown path, and boring tools.

## Options considered

1. **Plain shell scripts over SSH.** Minimal tooling, but idempotency must be
   hand-built for every step, and drift detection is non-existent.
2. **cloud-init only.** Runs once at first boot; re-running is not its model, so
   config changes mean rebuilding the server.
3. **Terraform + Ansible**, with a minimal cloud-init bootstrap.
4. **NixOS / immutable images (Packer).** Excellent reproducibility; much more
   unusual and heavier to learn and debug.

## Decision

Option 3, with strict separation of responsibilities:

| Layer      | Owns | Runs |
|------------|------|------|
| Terraform  | Droplet, SSH key registration, Cloud Firewall, Reserved IP, the two generated `local/` files | `make infra` |
| cloud-init | First-boot only: create the non-root admin user with your SSH key, disable root and password SSH immediately | once, by the provider |
| Ansible    | Everything on the host: packages, hardening, sysctl, nftables, fail2ban, unattended upgrades, unbound, WireGuard, `vpnctl` | `make configure` (re-runnable) |
| `vpnctl`   | The peer list and the rendered `wg0.conf` (ADR-0007) | on demand |

cloud-init deliberately does as little as possible: it exists so that the very first
SSH connection Ansible makes is already as the non-root, key-only user, and so the
window before Ansible runs never has password or root login enabled. Ansible
re-asserts the same settings, so it remains the source of truth.

Versions are pinned: Terraform `>= 1.6`, DigitalOcean provider `~> 2.0` (locked by
`.terraform.lock.hcl`, generated in Phase 2), ansible-core and Galaxy collections in
`requirements-dev.txt` / `ansible/requirements.yml`.

Terraform state is **local** and lives in `local/terraform.tfstate` (git-ignored),
because it contains the server IP. A remote backend is unnecessary for a
single-operator project; see ADR-0008.

## Tradeoffs

- (+) Each tool is used for what it is best at; both are boring and well-supported.
- (+) `make configure` is safe to re-run; Ansible reports drift as "changed".
- (−) Two tools to install on the laptop (Terraform, Ansible) instead of one.
- (−) Local Terraform state must be backed up (it is small and regenerable: losing
  it means importing or manually deleting three resources).
- (−) Reboots from unattended upgrades happen outside Ansible's control (ADR-0012).

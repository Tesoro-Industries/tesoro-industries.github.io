# ADR-0010: Testing and linting strategy

- Status: Accepted
- Date: 2026-11-09

## Context

Most of this project is infrastructure that can only be fully exercised against a
real VPS with privileged networking. Phase 1 runs in an unprivileged sandbox with
no cloud credentials. We want as much confidence as possible before Phase 2, and an
honest record of what was and was not executed.

## Options considered

- **Molecule + Docker** for Ansible roles: good, but containers cannot load nftables
  or WireGuard kernel modules faithfully, and no Docker daemon is available in
  Phase 1.
- **Testinfra/Goss against the real host**: valuable in Phase 2; overlaps with the
  built-in health check.
- **Unit tests for the tooling + rendering tests for templates + linters + the
  on-host health check as the integration test.**

## Decision

Three tiers:

1. **Static analysis** (`make lint`): `shellcheck`, `yamllint`, `ansible-lint`
   (production profile), `ansible-playbook --syntax-check`, `terraform fmt -check`,
   `tflint`, `terraform validate` (needs the provider download), `ruff` for Python,
   `gitleaks` for secrets.
2. **Unprivileged tests** (`make test`, pytest):
   - `vpnctl`: registry operations, address allocation, validation, config
     rendering, apply/revoke command sequences (with a fake command runner),
     locking, atomic writes, backup/restore round trip, health-check evaluation.
     Uses the real `wg` binary for key generation when installed.
   - `bin/vpn`: client config rendering (full/split tunnel, DNS always in
     `AllowedIPs`, exclusions), SSH command construction and quoting, JSON
     contract with `vpnctl`. An end-to-end test wires `bin/vpn` to `vpnctl` with
     the SSH hop replaced by a local subprocess.
   - Ansible templates: rendered with Jinja2 for both IPv6 modes and asserted
     structurally (policies, ports, interface scoping); `nft -c` is run on the
     render when the environment permits.
   - Repository hygiene: no key-shaped strings or real IPs in tracked files.
3. **On-host verification** (Phase 2): `make configure` twice (second run must
   report zero changes), `vpn health`, and the manual leak tests in
   `docs/leak-testing.md` from each device.

CI (`.github/workflows/vpn-ci.yml`) runs tiers 1 and 2 on every push touching
`vpn/`.

## Tradeoffs

- (+) Fast, runs anywhere, catches the logic bugs most likely to cause outages
  (address collisions, broken configs, wrong AllowedIPs).
- (−) Kernel-level behaviour (forwarding, NAT, nftables semantics, WireGuard
  handshakes) is only verified on the real host in Phase 2. HANDOFF.md tracks this
  per component.

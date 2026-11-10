# HANDOFF

Status as of the end of Phase 1 (cloud sandbox, no credentials, no real server),
plus a 2026-11-10 follow-up that added real-packet integration tests in Linux
network namespaces (see "Integration lab" below).

Verification labels used throughout:
- **Verified**: ran in this environment and passed
- **Statically checked**: linted or validated only, not executed
- **Unverified**: written but not run

Phase 1 toolchain: Python 3.13.18 and 3.9.25, ansible-core 2.22.0, ansible-lint
26.11.0 (production profile), ansible.posix 2.1.0, yamllint 1.38.0, ruff 0.17.4,
pytest 9.2.0, Terraform 1.13.4, tflint 0.59.1, gitleaks 8.28.0, shellcheck
(Ubuntu 24.04), wireguard-tools, age, qrencode, nftables, unbound, openssh-server,
fail2ban and cloud-init 26.2 (Ubuntu 24.04 packages). Follow-up: wireguard-go
0.0.20230223 (Ubuntu 24.04), because the sandbox kernel has no WireGuard
module. The sandbox kernel also boots with `ipv6.disable=1`, so **no IPv6 path
was exercised with real packets** here.

### Integration lab (`tests/test_netns_integration.py`)

Client, server and "internet" network namespaces are joined by veth pairs. The
server namespace runs the nftables ruleset and unbound config **rendered from the
Ansible templates**, plus a WireGuard interface managed by the real `vpnctl`.
Clients bring up configs produced by `bin/vpn` with `wg-quick`. 12 tests pass and
2 skip (IPv6). Each of four deliberate breakages was caught: removing NAT,
opening all TCP, revoking without a live sync, and exposing DNS on the WAN.

Verified there (IPv4, wireguard-go, not the kernel module, not DigitalOcean):
real handshakes; NAT so websites see the server's address; DNS answered by
unbound through the tunnel; unbound starting before `wg0` exists (ip-freebind);
from the internet only SSH is reachable, and DNS/53 and other ports are blocked
even with a listener present; tunnel clients cannot reach other server ports;
peer-to-peer is blocked; spoofed sources are dropped; **revocation cuts a
connected peer off immediately while the other peer keeps working**; a
split-tunnel peer routes only its listed range, and DNS still goes through the
tunnel; reloading the ruleset keeps foreign tables (fail2ban's).

The IPv6 cases (NAT66 egress, IPv6 DNS, IPv6 WAN exposure, IPv6 `block` mode)
could not run in the sandbox, but **pass in CI** on GitHub runners, which have
IPv6. In CI all 14 lab tests pass.

---

## 1. What's done

| Component | Path | Status | Evidence |
|-----------|------|--------|----------|
| ADRs (12) | `docs/adr/` | n/a (docs) | |
| Server peer tool `vpnctl` | `server/vpnctl.py` | **Verified** (unit level + live interface in netns lab) | 71 tests: validation, allocation, rendering, add/revoke/rollback, lock, atomic writes, health logic, backup/restore with malicious archives. Real `wg pubkey` and `wg-quick strip` used. Passes on Python 3.13 and 3.9. |
| Laptop CLI `bin/vpn` | `bin/vpn` | **Verified** (unit + local end-to-end) | 23 tests. Split-tunnel maths, rendering, SSH quoting (injection test), `.env` parsing. End-to-end add → list → revoke → backup → restore against the real `vpnctl` in a subprocess, with real `wg` and `age`. Python 3.13 and 3.9. The **SSH hop itself is Unverified.** |
| Client config validity | | **Verified** (wg-quick, IPv4) | Parsed by `wg-quick strip`. Brought up by `wg-quick` in the netns lab and carried traffic; IPv6 lines removed there because the kernel lacks IPv6. Not imported into any app. |
| Terraform templates (cloud-init, ssh_config, inventory) | `terraform/templates/` | **Verified** | Rendered by real `terraform` 1.13.4; cloud-init output passes `cloud-init schema`. |
| Terraform resources | `terraform/*.tf` | **Statically checked** (incl. provider schema) | `terraform fmt`, `tflint`, and **`terraform validate` passes in CI** against the real DigitalOcean provider (PR #1). Nothing has been applied. |
| Ansible roles / playbook | `ansible/` | **Statically checked** | `ansible-lint --strict` (production), `--syntax-check`, `yamllint --strict`. Never run against a host. |
| nftables ruleset | `roles/firewall/templates/nftables.conf.j2` | **Verified** (IPv4 real packets; IPv6 syntax only) | `nft -c` passes for both modes and structure is asserted. IPv4 filtering and NAT verified with real packets in the netns lab (above). IPv6 rules (NAT66, block mode) not exercised with packets. |
| unbound config | `roles/unbound/` | **Verified** (local answers; DoT upstream unverified) | `unbound-checkconf` passes. In the netns lab it served queries through the tunnel from a local zone and was unreachable from the WAN. The **DoT forward to Quad9 and DNSSEC validation were not exercised** (no internet in the lab). |
| sshd hardening | `roles/ssh_hardening/` | **Verified** (config only) | `sshd -T` on the drop-in followed by a hostile later file (like `50-cloud-init.conf`): root/password login stay off. |
| fail2ban config | `roles/fail2ban/` | **Verified** (config only) | `fail2ban-client --test` against the stock Ubuntu config plus ours. No bans tested. |
| Unattended upgrades, journald, sysctl | roles | **Statically checked** + rendered | Templates rendered and asserted; sysctl ordering (accept_ra before forwarding) asserted. Not applied. |
| Ansible → `vpnctl` JSON contract | `roles/wireguard/templates/vpnctl.json.j2` | **Verified** | Rendered JSON parsed by `vpnctl.ServerParams` in tests. |
| Repo hygiene / secrets | `.gitignore`, `.gitleaks.toml`, `tests/test_repo_hygiene.py` | **Verified** | Hygiene test passes; gitleaks finds nothing in the repo and **does** detect a planted WireGuard key. |
| Lint runner | `scripts/lint.sh`, `make lint` | **Verified** | `make lint` → all PASS except `terraform validate` (SKIP, see above). |
| Test runner | `make test` | **Verified** | 139 passed, 2 skipped (IPv6 integration tests; kernel lacks IPv6). As non-root the integration module skips. |
| Makefile provisioning targets | `Makefile` | **Unverified** | `make help` ran. `init`, `plan`, `infra`, `up`, `configure`, `check`, `health`, `backup`, `destroy` need credentials or a server. |
| CI workflow | `.github/workflows/vpn-ci.yml` | **Verified** | Green on PR #1: strict lint, full test suite, the root-only netns lab **with IPv6**, and the Python 3.9 job. |
| Docs | `README.md`, `docs/leak-testing.md` | n/a | Commands in them are Unverified until Phase 2. |
| Anything on a real VPS or device | | **Unverified** | Not possible in the sandbox. |

**Stubbed / not built (intentional, documented):** server key rotation is a
manual procedure (README); backups are manual (ADR-0009); there is no MTU
setting (default 1420, troubleshooting tells you to add `MTU = 1280`). There are
no TODO stubs in the code.

---

## 2. Phase 2 checklist (desktop)

Run from `vpn/` unless noted. Update §1 statuses as you go.

**A. Repository**

1. [x] GitHub push access fixed; branch pushed; draft PR #1 opened.
2. [ ] Decide whether to keep the project in this public Pages repository (see
   §4). To extract it with history:
   `git subtree split --prefix=vpn -b vpn-only && git push <new-private-repo-url> vpn-only:main`
3. [x] CI on PR #1 is green (2026-11-10). It checked: especially `terraform validate`
   (first real provider-schema check) and the root-only step. That step runs the
   netns integration lab **with IPv6**, the first real-packet check of NAT66 and
   block mode. If those two tests fail, fix them before provisioning.

**B. Laptop setup**

4. [ ] `brew install python@3.13 wireguard-tools qrencode age && brew tap hashicorp/tap && brew install hashicorp/tap/terraform`
5. [ ] `ssh-keygen -t ed25519 -f ~/.ssh/vpn_ed25519 -C "vpn admin"` (use a passphrase)
6. [ ] `age-keygen -o ~/vpn-backup-identity.txt`, then move the identity file into your password manager.
7. [ ] `cp .env.example .env` and fill in `DIGITALOCEAN_TOKEN`, `VPN_AGE_RECIPIENT`, `VPN_AGE_IDENTITY`.
8. [ ] `cp terraform/terraform.tfvars.example terraform/terraform.tfvars` and set the region and key paths.
9. [ ] `make init`, then commit the lock file:
   `git add terraform/.terraform.lock.hcl && git commit -m "vpn: pin Terraform provider versions"`
10. [ ] `make lint`. `terraform validate` now runs and must PASS. If it fails on
    a DigitalOcean attribute, fix `terraform/main.tf` (see §4, risk 3).

**C. Provision and configure**

11. [ ] `make plan`. Expect 7 resources: SSH key, Droplet, Reserved IP, its
    assignment, firewall, and 2 local files.
12. [ ] `make up`
13. [ ] `make configure` again. **Must show `changed=0`** (idempotency). Record the result.
14. [ ] `make health`. All checks PASS.
15. [ ] Run `make check` and confirm it reports no changes.

**D. Hardening checks (from your laptop, outside the VPN)**

16. [ ] `ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -F local/ssh_config vpn` → `Permission denied (publickey)`.
17. [ ] `ssh root@$(terraform -chdir=terraform output -raw exit_ipv4)` → denied.
18. [ ] Port scan: `nmap -Pn -p- $(terraform -chdir=terraform output -raw exit_ipv4)`. Only 22 open. Then `sudo nmap -sU -p 53,51820 <same>`: 53 must not be open.
19. [ ] Not an open resolver: `dig +time=3 @$(terraform -chdir=terraform output -raw exit_ipv4) example.com` times out.
20. [ ] `make ssh`, then `sudo nft list ruleset` (shows vpn_filter, vpn_nat and, after a ban, f2b-table), `sudo fail2ban-client status sshd`, and `sudo unattended-upgrade --dry-run --debug 2>&1 | tail`.

**E. Peers and devices**

21. [ ] `bin/vpn peer add phone` and scan the QR code (iOS or Android).
22. [ ] `bin/vpn peer add laptop --no-qr` and import `local/peers/laptop.conf` (macOS/Windows).
23. [ ] Optional: test the `--public-key` flow with the macOS or Windows app.
24. [ ] `bin/vpn peer list`. Recent handshakes are shown.
25. [ ] Revocation drill: `bin/vpn peer add revoke-test`, connect a device, `ping 10.99.0.1`, then `bin/vpn peer revoke revoke-test --yes`. Ping must stop within seconds, with no restart, and `make health` must still PASS.
26. [ ] Split-tunnel check: `bin/vpn peer add split-test --exclude 192.168.1.0/24` (use your LAN), then run leak test §6.
27. [ ] Mobile keepalive: phone on cellular, screen locked 10+ minutes. The tunnel still works without reconnecting.

**F. Leak tests**

28. [ ] Run [docs/leak-testing.md](docs/leak-testing.md) on every device and fill in its results table.
29. [ ] IPv6 block mode: add `vpn_ipv6_mode: block` under the host in `local/inventory.yml`, run `make configure`, and repeat leak test §2. Then remove the line and `make configure` again.

**G. Resilience**

30. [ ] Reboot test: `make ssh` then `sudo reboot`. After it comes back, `make health` passes and clients reconnect on their own. This verifies boot ordering of nftables, wg-quick and unbound (ip-freebind).
31. [ ] Backup and restore drill:
    `make backup && terraform -chdir=terraform apply -replace=digitalocean_droplet.vpn`
    (the new Droplet gets a new SSH/exit IP; the Reserved IP endpoint stays). Then:
    `make wait-ssh configure && bin/vpn restore local/backups/<file>.tar.age --yes && make health`
    The phone must reconnect **without re-importing** its config.
32. [ ] Optional teardown drill on a throwaway: `make destroy`, confirm nothing
    is left in the DigitalOcean console, then `make up` again.

**H. Wrap-up**

33. [ ] Update §1 statuses, fix any findings, and add ADRs for any changed decisions.

---

## 3. What you need to supply

| Item | Needed for | Where it goes | Notes |
|------|------------|---------------|-------|
| DigitalOcean account (billing enabled) | Phase 2 | n/a | about US$6/month for `s-1vcpu-1gb`; the Reserved IP is free while attached |
| DigitalOcean API token, read + write | `make plan/infra/destroy` | `.env` → `DIGITALOCEAN_TOKEN` | Delete it after teardown |
| SSH key pair | everything that SSHes | `~/.ssh/vpn_ed25519{,.pub}`; paths in `terraform/terraform.tfvars` | A passphrase or hardware key (`ed25519-sk`) is strongly recommended |
| age identity | backups / restore | identity in your password manager; `age1…` recipient in `.env` → `VPN_AGE_RECIPIENT`; identity path in `VPN_AGE_IDENTITY` (optional) | |
| Region choice | Terraform | `terraform/terraform.tfvars` → `region` | Nearest region to you |
| Optional: your stable home/office CIDRs | tighter SSH firewall | `terraform.tfvars` → `ssh_allowed_cidrs` | |
| Domain name | **not needed** | — | The Reserved IP is the endpoint |
| GitHub write access for this session or your laptop | pushing the branch / PR | GitHub settings | see §4, item 2 |

---

## 4. Open questions and risks

1. **This repository is a public GitHub Pages site.** The brief said "empty repo".
   The project lives in `vpn/` so the site is untouched (ADR-0001). Once merged,
   the files are publicly readable, and Pages/Jekyll will also render the
   Markdown at `/vpn/…`. Nothing secret is committed, but publishing your
   infrastructure layout is unnecessary. **Recommendation:** extract to a private
   repository (checklist step 2) and do not merge this PR into the site's
   default branch.
2. ~~Push to GitHub was refused.~~ Resolved: the branch is pushed and draft
   PR #1 is open with green CI.
3. ~~Provider schema unverified.~~ Resolved: `terraform validate` passes in CI.
4. **Reserved IP reply path.** Clients connect to the Reserved IP, but the
   Droplet's own IP is its source address. WireGuard replies from the address a
   packet arrived on, and DigitalOcean translates anchor-IP traffic back to the
   Reserved IP, so this should work, but it is untested. **Recommendation:**
   verify at steps 21–24. Fallback: set `vpn_endpoint` to the Droplet IP in
   `local/inventory.yml`; you lose endpoint stability across rebuilds.
5. **Ubuntu 26.04 LTS.** It exists, but this project targets 24.04 (support
   until 2029). **Recommendation:** stay on 24.04 for v1; adding 26.04 means a
   new image slug, adding `"26.04"` to `vpn_supported_ubuntu_versions`, and
   re-running all of §2.
6. **fail2ban table after an nftables *restart*.** `systemctl restart nftables`
   runs `flush ruleset` on stop, which removes fail2ban's table until fail2ban
   restarts. Ansible only ever *reloads*, which is safe. **Recommendation:** use
   `reload`, or restart fail2ban after any manual nftables restart.
7. **MTU.** Clients use the wg-quick default (1420). Some mobile networks need
   less. The server clamps TCP MSS, which covers most cases. **Recommendation:**
   only if step 27 or real use shows stalls, add an optional `vpn_client_mtu`
   server parameter (a schema-compatible addition).
8. **Split-tunnel DNS on iOS/macOS.** Whether the OS sends *all* DNS to the
   tunnel resolver when the tunnel is not the default route is up to the OS and
   is unverified. **Recommendation:** check in step 26 and document the result.
9. **Passwordless sudo and SSH open to the world** (ADR-0012). **Recommendation:**
   use a hardware-backed SSH key, and set `ssh_allowed_cidrs` if your networks
   are stable.
10. **TOFU host key** on first connection. Accepted risk (README threat model).
    Possible mitigation (unverified): cloud-init prints host key fingerprints to
    the serial console at first boot; if DigitalOcean's Recovery Console shows
    that output, compare it with `ssh-keygen -lf local/known_hosts`.
11. **Manual backups** (ADR-0009). **Recommendation:** run `make backup` after
    each peer change. Automating it would mean putting credentials on the
    server, which v1 avoids.
12. **GitHub Actions are pinned by tag, not commit SHA.** **Recommendation:** pin
    to SHAs and enable Dependabot for `github-actions` after extracting the repo.
13. **Laptop needs Python ≥ 3.13 for the Ansible venv** (ansible-core 2.22).
    `bin/vpn` alone works on 3.9. If 3.13 is a problem, pin an older
    ansible-core in `requirements-dev.txt` and re-run `make lint test`.
14. **Automatic reboots at 04:30 UTC.** **Recommendation:** set
    `unattended_upgrades_reboot_time` (in `local/inventory.yml` or
    `group_vars/all.yml`) to a time that is night for you.

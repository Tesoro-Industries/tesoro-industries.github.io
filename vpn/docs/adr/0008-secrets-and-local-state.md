# ADR-0008: Secrets and local state convention

- Status: Accepted
- Date: 2026-11-09

## Context

Keys, tokens and IP addresses must never be committed. This repository is likely
public (ADR-0001), which makes this a hard requirement rather than hygiene.

## Options considered

1. **Encrypted secrets in the repo** (sops, ansible-vault, git-crypt). Useful for
   teams; adds a key-management problem and one misconfiguration leaks history
   forever.
2. **Secrets manager** (1Password CLI, Vault). Good, but an extra dependency.
3. **Nothing secret in the repository at all.** One git-ignored directory holds all
   state; the repository contains only code and `*.example` files.

## Decision

Option 3.

- **`.env`** (from `.env.example`): environment variables for the laptop —
  `DIGITALOCEAN_TOKEN`, `VPN_AGE_RECIPIENT`, optional overrides. Loaded by the
  Makefile. Git-ignored.
- **`terraform/terraform.tfvars`** (from `terraform.tfvars.example`): your SSH public
  key path, region, allowed SSH source ranges. Git-ignored.
- **`local/`** — the single local-only directory, created with mode 0700:
  - `terraform.tfstate*` — contains the server IP
  - `inventory.yml`, `ssh_config`, `known_hosts` — generated connection details
  - `peers/*.conf` — client configs (contain client private keys)
  - `backups/*.tar.age` — encrypted server backups
- **Server secrets** stay on the server under `/etc/wireguard` (0700) — see the key
  table in ADR-0007.

Enforcement, in layers:

1. `.gitignore` with an allow-list style for `local/` (everything in it ignored).
2. `gitleaks` in CI and in `make lint`, with a rule for WireGuard keys.
3. A repository test (`tests/test_repo_hygiene.py`) that fails if any tracked file
   contains a WireGuard-key-shaped string or a non-documentation IPv4 address
   (RFC 5737 / RFC 3849 example ranges and the private tunnel ranges are allowed).

## Tradeoffs

- (+) Nothing to decrypt, rotate or leak in git history.
- (−) `local/` is a single point of loss: back it up (it is small) with your normal
  laptop backups or a password manager. Losing it is recoverable: server state is
  backed up separately, Terraform state can be re-imported, peers can be re-added.

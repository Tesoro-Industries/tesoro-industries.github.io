# HANDOFF

Living status document. Updated as work lands, not just at the end.

Verification labels:
- **Verified** — ran it in this environment and it passed
- **Statically checked** — linted/validated only
- **Unverified** — written but not run

## 1. Status

Phase 1 in progress. Plan (each item is one or more commits):

1. ADRs and repo plan — done (docs only)
2. Repo scaffolding: Makefile, lint config, CI
3. `server/vpnctl` + tests
4. `bin/vpn` + tests
5. Terraform (DigitalOcean) + cloud-init
6. Ansible roles
7. Template rendering tests, repo hygiene test
8. README, leak-testing guide
9. Final HANDOFF, PR

## 2. Phase 2 checklist

To be written as components land.

## 3. What you need to supply

To be written.

## 4. Open questions and risks

- **This repository is a public GitHub Pages site** (see ADR-0001). The project is in
  `vpn/` and commits no secrets, but it will be publicly readable once merged.
  Recommendation: extract to a private repo with `git subtree split --prefix=vpn`.

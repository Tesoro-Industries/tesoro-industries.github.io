# ADR-0001: Repository layout and decision records

- Status: Accepted
- Date: 2026-11-09

## Context

The brief assumed an empty repository. The repository this session was attached to
(`tesoro-industries.github.io`) is not empty: it is a live GitHub Pages site (an
`index.html` at the root plus per-app privacy/support pages). Anything committed to
its default branch is published to the web by Pages, and the repository is very
likely public (organisation `*.github.io` Pages sites on free plans must be).

We need somewhere to put the VPN project now, without breaking the site, and in a
form that is easy to move later.

## Options considered

1. **Put the project at the repository root** (`/docs/adr`, `/HANDOFF.md`, ...).
   Matches the brief literally, but interleaves infrastructure code with the
   website's files and makes later extraction noisy.
2. **Put the project in a self-contained subdirectory (`vpn/`).** Every path in the
   brief (`/docs/adr/`, `/HANDOFF.md`, ...) is interpreted relative to `vpn/`.
   The site is untouched; `git subtree split --prefix=vpn` extracts the project
   with full history into its own repository later.
3. **Stop and ask for a new repository.** The brief explicitly asks not to stop.

## Decision

Option 2. The project root is `vpn/`. The only file outside it is the CI workflow
`.github/workflows/vpn-ci.yml`, which GitHub requires at the repository root; it is
path-filtered to `vpn/**`.

Layout:

```
vpn/
  README.md            quickstart, architecture, threat model, troubleshooting
  HANDOFF.md           live status + Phase 2 checklist
  Makefile             single entry point for provisioning, lint, test
  .env.example         documented environment variables (copy to .env)
  bin/vpn              operator CLI (runs on your laptop)
  server/vpnctl        server-side peer registry tool (installed by Ansible)
  terraform/           DigitalOcean infrastructure (droplet, firewall, reserved IP)
  ansible/             host configuration (roles per concern)
  tests/               unprivileged unit / rendering tests (pytest)
  scripts/             lint and helper scripts
  docs/adr/            architecture decision records (this directory)
  docs/leak-testing.md DNS / IPv4 / IPv6 leak tests
  local/               GIT-IGNORED: all secrets and machine-specific state
```

Decisions are recorded as short ADRs (context, options, decision, tradeoffs) in
`docs/adr/`, numbered sequentially and never rewritten once accepted — a changed
decision gets a new ADR that supersedes the old one.

## Tradeoffs

- (+) Zero impact on the website; trivially extractable.
- (−) **Publication risk:** because this is a Pages repository, once merged to the
  default branch these files are publicly readable (Pages renders Markdown via
  Jekyll). The project is designed so that this is safe — no keys, tokens, IP
  addresses or hostnames are ever committed (see ADR-0008) — but moving it to a
  private repository is still recommended. See HANDOFF.md, open questions.
- (−) Paths in the brief are offset by `vpn/`.

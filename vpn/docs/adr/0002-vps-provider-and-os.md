# ADR-0002: VPS provider and operating system

- Status: Accepted
- Date: 2026-11-09

## Context

The server is one small Linux VPS on Ubuntu LTS. The code should be
provider-agnostic, but the default path should work end-to-end with one mainstream
provider. A WireGuard server for a handful of personal devices needs ~1 vCPU,
512 MB–1 GB RAM, a static public IPv4, native IPv6, and modest egress.

## Options considered

| Provider      | Terraform provider | Cloud firewall | Stable IP across rebuilds | IPv6 | Notes |
|---------------|--------------------|----------------|---------------------------|------|-------|
| DigitalOcean  | Official, mature   | Yes (free)     | Reserved IP (free while attached) | Yes | Global regions, simple API, very widely documented |
| Hetzner Cloud | Official, mature   | Yes (free)     | Primary IP                 | Yes  | Cheapest; fewer US regions; account verification can be slow |
| Vultr         | Official           | Yes            | Reserved IP                | Yes  | Fine, smaller community |
| AWS Lightsail | Via AWS provider   | Yes            | Static IP                  | Yes  | Heavier account/IAM setup for a personal project |

## Decision

**DigitalOcean** is the default, using:

- a `s-1vcpu-1gb` Droplet (≈ US$6/month; the 512 MB size also works but leaves
  little headroom for apt upgrades),
- a **Reserved IP** as the WireGuard endpoint, so client configs survive a server
  rebuild (destroy/recreate the Droplet, restore the backup, phones keep working),
- a **DigitalOcean Cloud Firewall** as a second, provider-side layer in front of
  the host firewall.

**Ubuntu 24.04 LTS** (`ubuntu-24-04-x64`) is the default and the only release the
Ansible roles assert as supported. It has kernel WireGuard, nftables, systemd and
Python 3.12 out of the box and is supported until 2029.

Provider-agnosticism is achieved by a hard seam: Terraform is the *only*
provider-specific component. Its outputs are two plain files in `local/`
(an Ansible inventory and an SSH config). Any Ubuntu 24.04 host with the cloud-init
user-data from `terraform/templates/cloud-init.yaml.tftpl` (or an equivalent manual
user setup) and those two hand-written files works with everything else.

## Tradeoffs

- (+) Mainstream, well-documented, one API token, free firewall and reserved IP.
- (−) Hetzner would be roughly half the price.
- (−) A Reserved IP is IPv4 only. The tunnel *carries* IPv6 (ADR-0005) but clients
  connect to the server over IPv4. This is deliberate: an IPv4 endpoint works from
  every network, whereas an IPv6-only endpoint would not.
- (−) Ubuntu 26.04 LTS exists, but its image slug and package behaviour (notably
  fail2ban and sshd defaults) are unverified here. Moving to it is a Phase 2
  decision recorded in HANDOFF.md.
- Trust: the provider controls the hypervisor and can read memory and disk. No VPS
  choice removes this; it is listed in the threat model.

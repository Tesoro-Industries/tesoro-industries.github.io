# ADR-0009: Backup and restore

- Status: Accepted
- Date: 2026-11-09

## Context

The only irreplaceable server state is the server private key (all client configs
pin its public key) and the peer registry (public keys, PSKs, addresses). Everything
else is reproducible from this repository. A restore must make existing client
configs work again on a rebuilt server.

## Options considered

1. **Provider snapshots.** Easy, but costs money, captures everything including
   logs, and is provider-specific.
2. **Copy files with scp to the laptop in plaintext.** Leaves a server private key
   in plaintext on the laptop.
3. **Stream a tarball over SSH and encrypt it on the laptop before it touches disk,
   with `age` to a public recipient.**

## Decision

Option 3.

- `vpnctl backup` writes a tar archive (server key, `peers.json`, `vpnctl.json`,
  a manifest with schema version) to stdout. Nothing is written to the server disk.
- `vpn backup` runs it over SSH and pipes it straight into `age -r $VPN_AGE_RECIPIENT`,
  writing `local/backups/vpn-<UTC timestamp>.tar.age`. The plaintext never touches
  the laptop's disk.
- `vpn restore FILE` runs `age -d -i <identity>` locally and streams the plaintext
  into `vpnctl restore` over SSH, which validates the manifest and every key,
  installs the files atomically and re-applies the configuration.
- `age` was chosen over GPG because it is a single small, well-specified tool with
  no keyring; the identity file belongs in your password manager. Encryption is to
  a recipient (public key), so taking a backup needs no secret at all.

Recovery path after loss of the server: `make up` → `vpn restore FILE` → clients
reconnect (the Reserved IP keeps the endpoint stable). Ansible will have generated
a fresh server key on the new host; the restore replaces it.

## Tradeoffs

- (+) Small, provider-agnostic, encrypted at rest, no secret needed to back up.
- (−) Manual: there is no scheduled backup. The peer list changes rarely, so run
  `vpn backup` after adding or revoking peers. (Automated off-site backup would
  require storing credentials on the server — deliberately avoided in v1.)
- (−) Losing the age identity makes backups unrecoverable; the fallback is
  re-provisioning and re-adding peers.

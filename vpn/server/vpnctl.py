#!/usr/bin/env python3
"""vpnctl - WireGuard peer registry and live configuration for a single server.

Installed by Ansible to /usr/local/sbin/vpnctl and run as root (via sudo).

Responsibilities (see docs/adr/0007-peer-management.md):
  * Own the peer registry (/etc/wireguard/peers.json).
  * Render /etc/wireguard/<iface>.conf from the registry plus the
    Ansible-owned server parameters (/etc/wireguard/vpnctl.json).
  * Apply changes live with `wg syncconf`, so adding or revoking a peer takes
    effect immediately without restarting the interface.
  * Health check, backup and restore of server state.

vpnctl never generates or sees client private keys. All cryptography is done by
the official `wg` tool. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import datetime
import errno
import fcntl
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Callable

SCHEMA = 1
VERSION = "1.0.0"

DEFAULT_CONFIG_DIR = Path("/etc/wireguard")
PARAMS_FILE = "vpnctl.json"
REGISTRY_FILE = "peers.json"
SERVER_KEY_FILE = "server.key"
LOCK_FILE = ".vpnctl.lock"

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_=+.-]{1,15}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
IPV6_MODES = ("tunnel", "block")

# Backup archive members. Anything else in an archive is rejected on restore.
BACKUP_MANIFEST = "manifest.json"
BACKUP_MEMBERS = (BACKUP_MANIFEST, SERVER_KEY_FILE, REGISTRY_FILE, PARAMS_FILE)
BACKUP_MAX_MEMBER_BYTES = 1024 * 1024

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2


class VpnctlError(Exception):
    """An expected, user-facing error. Printed without a traceback."""


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------


def validate_name(name: str) -> str:
    if not NAME_RE.match(name):
        raise VpnctlError(
            f"invalid peer name {name!r}: use 1-32 characters of a-z, 0-9 and '-', "
            "starting and ending with a letter or digit"
        )
    return name


def validate_key(key: str, what: str = "key") -> str:
    """Validate a WireGuard key: base64 of exactly 32 bytes."""
    key = key.strip()
    if len(key) != 44:
        raise VpnctlError(f"invalid {what}: expected 44 base64 characters")
    try:
        raw = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        raise VpnctlError(f"invalid {what}: not valid base64") from None
    if len(raw) != 32:
        raise VpnctlError(f"invalid {what}: does not decode to 32 bytes")
    return key


def validate_endpoint_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not HOSTNAME_RE.match(host):
        raise VpnctlError(f"invalid endpoint host {host!r}")
    return host


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ServerParams:
    """Server parameters. Owned by Ansible; vpnctl only reads them."""

    interface: str
    listen_port: int
    endpoint: str
    ipv4_network: ipaddress.IPv4Network
    ipv6_network: ipaddress.IPv6Network
    ipv6_mode: str
    client_keepalive: int
    dns: tuple[str, ...]

    @property
    def server_ipv4(self) -> ipaddress.IPv4Address:
        return self.ipv4_network.network_address + 1

    @property
    def server_ipv6(self) -> ipaddress.IPv6Address:
        return self.ipv6_network.network_address + 1

    @classmethod
    def from_dict(cls, data: dict) -> ServerParams:
        if not isinstance(data, dict):
            raise VpnctlError("server parameters: expected a JSON object")
        if data.get("schema") != SCHEMA:
            raise VpnctlError(f"server parameters: unsupported schema {data.get('schema')!r}")
        try:
            iface = str(data["interface"])
            port = int(data["listen_port"])
            endpoint = validate_endpoint_host(str(data["endpoint"]))
            v4 = ipaddress.IPv4Network(data["ipv4_network"], strict=True)
            v6 = ipaddress.IPv6Network(data["ipv6_network"], strict=True)
            mode = str(data["ipv6_mode"])
            keepalive = int(data["client_keepalive"])
            dns_raw = data.get("dns")
        except KeyError as exc:
            raise VpnctlError(f"server parameters: missing field {exc.args[0]!r}") from None
        except (TypeError, ValueError) as exc:
            raise VpnctlError(f"server parameters: {exc}") from None
        if not IFACE_RE.match(iface):
            raise VpnctlError(f"server parameters: invalid interface name {iface!r}")
        if not 1 <= port <= 65535:
            raise VpnctlError("server parameters: listen_port out of range")
        if mode not in IPV6_MODES:
            raise VpnctlError(f"server parameters: ipv6_mode must be one of {IPV6_MODES}")
        if not 0 <= keepalive <= 65535:
            raise VpnctlError("server parameters: client_keepalive out of range")
        if v4.prefixlen > 29:
            raise VpnctlError("server parameters: ipv4_network must be /29 or larger")
        if v6.prefixlen > 125:
            raise VpnctlError("server parameters: ipv6_network must be /125 or larger")
        if not v4.is_private or not v6.is_private:
            raise VpnctlError("server parameters: tunnel networks must be private ranges")
        params = cls(iface, port, endpoint, v4, v6, mode, keepalive, ())
        if dns_raw is None:
            dns = (str(params.server_ipv4), str(params.server_ipv6))
        else:
            if not isinstance(dns_raw, list) or not dns_raw:
                raise VpnctlError("server parameters: dns must be a non-empty list")
            try:
                dns = tuple(str(ipaddress.ip_address(d)) for d in dns_raw)
            except ValueError as exc:
                raise VpnctlError(f"server parameters: {exc}") from None
        return dataclasses.replace(params, dns=dns)

    def public_dict(self) -> dict:
        return {
            "interface": self.interface,
            "listen_port": self.listen_port,
            "endpoint": self.endpoint,
            "ipv4_network": str(self.ipv4_network),
            "ipv6_network": str(self.ipv6_network),
            "server_ipv4": str(self.server_ipv4),
            "server_ipv6": str(self.server_ipv6),
            "ipv6_mode": self.ipv6_mode,
            "client_keepalive": self.client_keepalive,
            "dns": list(self.dns),
        }


@dataclasses.dataclass(frozen=True)
class Peer:
    name: str
    public_key: str
    preshared_key: str | None
    ipv4: ipaddress.IPv4Address
    ipv6: ipaddress.IPv6Address
    created: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "public_key": self.public_key,
            "preshared_key": self.preshared_key,
            "ipv4": str(self.ipv4),
            "ipv6": str(self.ipv6),
            "created": self.created,
        }

    def public_dict(self) -> dict:
        """Everything except the preshared key."""
        data = self.to_dict()
        del data["preshared_key"]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Peer:
        try:
            psk = data.get("preshared_key")
            return cls(
                name=validate_name(str(data["name"])),
                public_key=validate_key(str(data["public_key"]), "public key"),
                preshared_key=None if psk is None else validate_key(str(psk), "preshared key"),
                ipv4=ipaddress.IPv4Address(data["ipv4"]),
                ipv6=ipaddress.IPv6Address(data["ipv6"]),
                created=str(data["created"]),
            )
        except KeyError as exc:
            raise VpnctlError(f"peer registry: missing field {exc.args[0]!r}") from None
        except ValueError as exc:
            raise VpnctlError(f"peer registry: {exc}") from None


@dataclasses.dataclass(frozen=True)
class Registry:
    peers: tuple[Peer, ...] = ()

    @classmethod
    def from_dict(cls, data: dict) -> Registry:
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise VpnctlError("peer registry: missing or unsupported schema")
        peers_raw = data.get("peers")
        if not isinstance(peers_raw, list):
            raise VpnctlError("peer registry: 'peers' must be a list")
        registry = cls(tuple(Peer.from_dict(p) for p in peers_raw))
        registry.check_unique()
        return registry

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "peers": [p.to_dict() for p in self.peers]}

    def check_unique(self) -> None:
        for attr in ("name", "public_key", "ipv4", "ipv6"):
            values = [getattr(p, attr) for p in self.peers]
            if len(values) != len(set(values)):
                raise VpnctlError(f"peer registry: duplicate {attr}")

    def find(self, name: str) -> Peer | None:
        for peer in self.peers:
            if peer.name == name:
                return peer
        return None

    def check_fits(self, params: ServerParams) -> None:
        for peer in self.peers:
            if peer.ipv4 not in params.ipv4_network or peer.ipv6 not in params.ipv6_network:
                raise VpnctlError(
                    f"peer {peer.name!r} has addresses outside the configured tunnel networks"
                )

    def allocate(self, params: ServerParams) -> tuple[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """Lowest free host offset (>= 2) in both networks.

        Offset 0 is the network address, 1 the server; the IPv4 broadcast address is
        never used. The IPv6 address uses the same offset, so a peer's two
        addresses are easy to correlate (10.x.y.5 <-> prefix::5).
        """
        used_v4 = {p.ipv4 for p in self.peers}
        used_v6 = {p.ipv6 for p in self.peers}
        v4net, v6net = params.ipv4_network, params.ipv6_network
        last_offset = min(v4net.num_addresses - 2, v6net.num_addresses - 1)
        for offset in range(2, last_offset + 1):
            v4 = v4net.network_address + offset
            v6 = v6net.network_address + offset
            if v4 not in used_v4 and v6 not in used_v6:
                return v4, v6
        raise VpnctlError("no free tunnel addresses left in the configured networks")

    def with_peer(self, peer: Peer) -> Registry:
        if self.find(peer.name):
            raise VpnctlError(f"peer {peer.name!r} already exists")
        if any(p.public_key == peer.public_key for p in self.peers):
            raise VpnctlError("a peer with this public key already exists")
        return Registry(self.peers + (peer,))

    def without_peer(self, name: str) -> tuple[Registry, Peer]:
        peer = self.find(name)
        if peer is None:
            raise VpnctlError(f"no such peer {name!r}")
        return Registry(tuple(p for p in self.peers if p.name != name)), peer


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def render_server_config(params: ServerParams, private_key: str, registry: Registry) -> str:
    """Render the wg-quick configuration for the server interface."""
    lines = [
        "# Managed by vpnctl. Do not edit: changes are overwritten.",
        "# Add/revoke peers with `vpnctl` (or `vpn peer ...` from your laptop).",
        "[Interface]",
        (
            f"Address = {params.server_ipv4}/{params.ipv4_network.prefixlen}, "
            f"{params.server_ipv6}/{params.ipv6_network.prefixlen}"
        ),
        f"ListenPort = {params.listen_port}",
        f"PrivateKey = {private_key}",
        # The firewall lives in /etc/nftables.conf, not in PostUp hooks (ADR-0004).
        "SaveConfig = false",
    ]
    for peer in peers_by_address(registry.peers):
        lines += [
            "",
            f"# peer: {peer.name} (created {peer.created})",
            "[Peer]",
            f"PublicKey = {peer.public_key}",
        ]
        if peer.preshared_key:
            lines.append(f"PresharedKey = {peer.preshared_key}")
        lines.append(f"AllowedIPs = {peer.ipv4}/32, {peer.ipv6}/128")
    return "\n".join(lines) + "\n"


def peers_by_address(peers: Sequence[Peer]) -> list[Peer]:
    return sorted(peers, key=lambda p: int(p.ipv4))


# --------------------------------------------------------------------------
# Environment: filesystem and command execution (injectable for tests)
# --------------------------------------------------------------------------

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def default_runner(
    cmd: Sequence[str], *, input: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(cmd), input=input, capture_output=True, text=True, check=check, timeout=60
        )
    except FileNotFoundError:
        raise VpnctlError(f"command not found: {cmd[0]}") from None
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() or f"exit status {exc.returncode}"
        raise VpnctlError(f"`{' '.join(cmd[:2])}` failed: {detail}") from None
    except subprocess.TimeoutExpired:
        raise VpnctlError(f"`{' '.join(cmd[:2])}` timed out") from None


@dataclasses.dataclass
class Env:
    config_dir: Path = DEFAULT_CONFIG_DIR
    sys_root: Path = Path("/sys")
    proc_root: Path = Path("/proc")
    run_root: Path = Path("/run")
    runner: Runner = default_runner

    @property
    def params_path(self) -> Path:
        return self.config_dir / PARAMS_FILE

    @property
    def registry_path(self) -> Path:
        return self.config_dir / REGISTRY_FILE

    @property
    def key_path(self) -> Path:
        return self.config_dir / SERVER_KEY_FILE

    def conf_path(self, params: ServerParams) -> Path:
        return self.config_dir / f"{params.interface}.conf"

    def interface_up(self, iface: str) -> bool:
        return (self.sys_root / "class" / "net" / iface).exists()


def atomic_write(path: Path, data: bytes | str, mode: int = 0o600) -> None:
    """Write a file atomically: temp file in the same directory, fsync, rename."""
    if isinstance(data, str):
        data = data.encode()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def locked(env: Env, timeout: float = 10.0) -> Iterator[None]:
    """Exclusive advisory lock so concurrent vpnctl invocations cannot race."""
    fd = os.open(env.config_dir / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                if time.monotonic() >= deadline:
                    raise VpnctlError("another vpnctl is running; try again") from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def load_json(path: Path, what: str) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise VpnctlError(f"{what} not found at {path}") from None
    except json.JSONDecodeError as exc:
        raise VpnctlError(f"{what} at {path} is not valid JSON: {exc}") from None


def load_params(env: Env) -> ServerParams:
    return ServerParams.from_dict(load_json(env.params_path, "server parameters"))


def load_registry(env: Env) -> Registry:
    if not env.registry_path.exists():
        return Registry()
    return Registry.from_dict(load_json(env.registry_path, "peer registry"))


def save_registry(env: Env, registry: Registry) -> None:
    atomic_write(env.registry_path, json.dumps(registry.to_dict(), indent=2) + "\n")


def read_server_key(env: Env) -> str:
    try:
        return validate_key(env.key_path.read_text(), "server private key")
    except FileNotFoundError:
        raise VpnctlError(f"server private key not found at {env.key_path}") from None


def server_public_key(env: Env, private_key: str) -> str:
    out = env.runner(["wg", "pubkey"], input=private_key + "\n").stdout
    return validate_key(out, "server public key")


# --------------------------------------------------------------------------
# Operations
# --------------------------------------------------------------------------


def apply_config(env: Env, params: ServerParams, registry: Registry) -> bool:
    """Render the interface config and sync it into the running interface.

    Returns True if the running interface was updated, False if it is down (the
    config is written and will be used when wg-quick@<iface> starts).
    """
    registry.check_fits(params)
    private_key = read_server_key(env)
    conf = env.conf_path(params)
    atomic_write(conf, render_server_config(params, private_key, registry))
    if not env.interface_up(params.interface):
        return False
    stripped = env.runner(["wg-quick", "strip", str(conf)]).stdout
    # Equivalent to `wg syncconf wg0 <(wg-quick strip wg0)`: changes only what
    # differs, so other peers' sessions are not disturbed. Removed peers are
    # dropped from the kernel immediately.
    env.runner(["wg", "syncconf", params.interface, "/dev/stdin"], input=stripped)
    return True


def change_registry(env: Env, params: ServerParams, old: Registry, new: Registry) -> bool:
    """Persist `new` and apply it; on failure restore `old` (best effort)."""
    save_registry(env, new)
    try:
        return apply_config(env, params, new)
    except BaseException:
        save_registry(env, old)
        with contextlib.suppress(Exception):
            apply_config(env, params, old)
        raise


def today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def add_peer(
    env: Env, name: str, public_key: str, preshared_key: str | None
) -> tuple[Peer, ServerParams, str, bool]:
    validate_name(name)
    validate_key(public_key, "public key")
    if preshared_key is not None:
        validate_key(preshared_key, "preshared key")
    with locked(env):
        params = load_params(env)
        old = load_registry(env)
        private_key = read_server_key(env)
        server_pub = server_public_key(env, private_key)
        if public_key == server_pub:
            raise VpnctlError("peer public key must not equal the server's public key")
        ipv4, ipv6 = old.allocate(params)
        peer = Peer(name, public_key, preshared_key, ipv4, ipv6, today())
        new = old.with_peer(peer)
        live = change_registry(env, params, old, new)
    return peer, params, server_pub, live


def revoke_peer(env: Env, name: str) -> tuple[Peer, bool]:
    validate_name(name)
    with locked(env):
        params = load_params(env)
        old = load_registry(env)
        new, peer = old.without_peer(name)
        live = change_registry(env, params, old, new)
    return peer, live


def live_handshakes(env: Env, params: ServerParams) -> dict[str, int] | None:
    """Map public key -> latest handshake (unix time, 0 = never). None if down.

    Reads in-memory kernel state only; nothing is stored (ADR-0011).
    """
    if not env.interface_up(params.interface):
        return None
    out = env.runner(["wg", "show", params.interface, "dump"]).stdout
    result: dict[str, int] = {}
    for line in out.splitlines()[1:]:  # first line describes the interface
        fields = line.split("\t")
        if len(fields) >= 5:
            try:
                result[fields[0]] = int(fields[4])
            except ValueError:
                result[fields[0]] = 0
    return result


def format_age(seconds: int) -> str:
    if seconds < 120:
        return f"{seconds}s ago"
    if seconds < 7200:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


# --------------------------------------------------------------------------
# Health check
# --------------------------------------------------------------------------

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str = ""


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _systemd_active(env: Env, *units: str) -> bool:
    for unit in units:
        res = env.runner(["systemctl", "is-active", "--quiet", unit], check=False)
        if res.returncode == 0:
            return True
    return False


def health_checks(env: Env) -> list[Check]:
    checks: list[Check] = []
    try:
        params = load_params(env)
        registry = load_registry(env)
        checks.append(Check("config", PASS, f"{len(registry.peers)} peer(s) registered"))
    except VpnctlError as exc:
        return [Check("config", FAIL, str(exc))]

    try:
        mode = env.key_path.stat().st_mode & 0o777
        read_server_key(env)
        checks.append(Check("server key", PASS if mode == 0o600 else FAIL, f"mode {mode:04o}"))
    except (OSError, VpnctlError) as exc:
        checks.append(Check("server key", FAIL, str(exc)))

    iface = params.interface
    if env.interface_up(iface):
        checks.append(Check("interface", PASS, f"{iface} is up"))
        port = env.runner(["wg", "show", iface, "listen-port"], check=False).stdout.strip()
        checks.append(
            Check(
                "listen port",
                PASS if port == str(params.listen_port) else FAIL,
                f"{port or 'unknown'} (expected {params.listen_port})",
            )
        )
        live = set(env.runner(["wg", "show", iface, "peers"], check=False).stdout.split())
        registered = {p.public_key for p in registry.peers}
        if live == registered:
            checks.append(Check("peers in sync", PASS, f"{len(live)} live"))
        else:
            checks.append(
                Check(
                    "peers in sync",
                    FAIL,
                    f"{len(live - registered)} live but not registered (revoked?), "
                    f"{len(registered - live)} registered but not live; run `vpnctl apply`",
                )
            )
    else:
        checks.append(Check("interface", FAIL, f"{iface} is down"))

    fwd4 = _read(env.proc_root / "sys/net/ipv4/ip_forward")
    checks.append(Check("ipv4 forwarding", PASS if fwd4 == "1" else FAIL, f"= {fwd4}"))
    fwd6 = _read(env.proc_root / "sys/net/ipv6/conf/all/forwarding")
    if params.ipv6_mode == "tunnel":
        checks.append(Check("ipv6 forwarding", PASS if fwd6 == "1" else FAIL, f"= {fwd6}"))

    units = [
        ("wireguard service", (f"wg-quick@{iface}.service",)),
        ("nftables service", ("nftables.service",)),
        ("unbound service", ("unbound.service",)),
        ("fail2ban service", ("fail2ban.service",)),
        ("ssh service", ("ssh.service", "ssh.socket")),
    ]
    for label, unit_names in units:
        ok = _systemd_active(env, *unit_names)
        checks.append(Check(label, PASS if ok else FAIL, "active" if ok else "not active"))

    tables_ok = all(
        env.runner(["nft", "list", "table", "inet", t], check=False).returncode == 0
        for t in ("vpn_filter", "vpn_nat")
    )
    checks.append(
        Check(
            "firewall tables",
            PASS if tables_ok else FAIL,
            "vpn_filter, vpn_nat loaded"
            if tables_ok
            else "missing; run `systemctl restart nftables`",
        )
    )

    uu = env.runner(
        ["apt-config", "shell", "UU", "APT::Periodic::Unattended-Upgrade"], check=False
    ).stdout
    checks.append(
        Check("unattended upgrades", PASS if "UU='1'" in uu else FAIL, uu.strip() or "unset")
    )

    sshd = env.runner(["sshd", "-T"], check=False).stdout.lower().splitlines()
    for setting in ("permitrootlogin no", "passwordauthentication no"):
        checks.append(
            Check(
                f"sshd {setting.split()[0]}",
                PASS if setting in sshd else FAIL,
                setting if setting in sshd else "NOT " + setting,
            )
        )

    resolver = str(params.server_ipv4)
    dig = ["dig", "+time=3", "+tries=1", f"@{resolver}"]
    answer = env.runner(dig + ["+short", "example.com", "A"], check=False)
    resolved = answer.returncode == 0 and answer.stdout.strip() != ""
    checks.append(
        Check(
            "dns resolves",
            PASS if resolved else FAIL,
            f"via {resolver}" if resolved else f"no answer from {resolver}",
        )
    )
    bogus = env.runner(dig + ["dnssec-failed.org", "A"], check=False).stdout
    checks.append(
        Check(
            "dnssec validation",
            PASS if "status: SERVFAIL" in bogus else WARN,
            "bogus domain rejected"
            if "status: SERVFAIL" in bogus
            else "dnssec-failed.org did not SERVFAIL (validation off or upstream issue)",
        )
    )

    if (env.run_root / "reboot-required").exists():
        checks.append(
            Check(
                "reboot",
                WARN,
                "reboot required; will happen at the unattended-upgrades reboot time",
            )
        )
    else:
        checks.append(Check("reboot", PASS, "not required"))
    return checks


# --------------------------------------------------------------------------
# Backup / restore
# --------------------------------------------------------------------------


def _tar_add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    info.mtime = int(time.time())
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    tar.addfile(info, io.BytesIO(data))


def write_backup(env: Env, out: io.BufferedIOBase) -> None:
    with locked(env):
        params = load_params(env)  # validates before we ship anything
        registry = load_registry(env)
        key = read_server_key(env)
        manifest = {
            "schema": SCHEMA,
            "vpnctl_version": VERSION,
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "interface": params.interface,
            "peers": len(registry.peers),
        }
        with tarfile.open(fileobj=out, mode="w|") as tar:
            _tar_add(tar, BACKUP_MANIFEST, (json.dumps(manifest, indent=2) + "\n").encode())
            _tar_add(tar, SERVER_KEY_FILE, (key + "\n").encode())
            _tar_add(tar, REGISTRY_FILE, (json.dumps(registry.to_dict(), indent=2) + "\n").encode())
            _tar_add(tar, PARAMS_FILE, env.params_path.read_bytes())


def read_backup(stream: io.BufferedIOBase) -> dict[str, bytes]:
    """Read and strictly validate a backup archive. Never extracts to disk."""
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for info in tar:
                if info.name not in BACKUP_MEMBERS:
                    raise VpnctlError(f"backup: unexpected member {info.name!r}")
                if not info.isfile():
                    raise VpnctlError(f"backup: {info.name!r} is not a regular file")
                if info.size > BACKUP_MAX_MEMBER_BYTES:
                    raise VpnctlError(f"backup: {info.name!r} is too large")
                if info.name in members:
                    raise VpnctlError(f"backup: duplicate member {info.name!r}")
                fh = tar.extractfile(info)
                if fh is None:  # pragma: no cover - isfile() guarantees a file object
                    raise VpnctlError(f"backup: cannot read {info.name!r}")
                members[info.name] = fh.read()
    except tarfile.TarError as exc:
        raise VpnctlError(f"backup: not a valid archive ({exc})") from None
    missing = set(BACKUP_MEMBERS) - set(members)
    if missing:
        raise VpnctlError(f"backup: missing {', '.join(sorted(missing))}")
    try:
        manifest = json.loads(members[BACKUP_MANIFEST])
    except json.JSONDecodeError:
        raise VpnctlError("backup: manifest is not valid JSON") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise VpnctlError("backup: unsupported manifest schema")
    return members


def restore_backup(env: Env, stream: io.BufferedIOBase) -> tuple[Registry, bool]:
    """Restore the server key and peer registry, then apply.

    The server parameters (vpnctl.json) are owned by Ansible and are NOT restored;
    the backup's copy is only used to warn about differences. Peers must fit the
    current tunnel networks.
    """
    members = read_backup(stream)
    key = validate_key(members[SERVER_KEY_FILE].decode(), "server private key")
    try:
        registry = Registry.from_dict(json.loads(members[REGISTRY_FILE]))
    except json.JSONDecodeError:
        raise VpnctlError("backup: peer registry is not valid JSON") from None
    with locked(env):
        params = load_params(env)
        registry.check_fits(params)
        old_key = env.key_path.read_bytes() if env.key_path.exists() else None
        old_registry = load_registry(env)
        atomic_write(env.key_path, key + "\n")
        try:
            save_registry(env, registry)
            live = apply_config(env, params, registry)
        except BaseException:
            if old_key is not None:
                atomic_write(env.key_path, old_key)
            save_registry(env, old_registry)
            raise
    return registry, live


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def emit(obj: dict) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def cmd_add(env: Env, args: argparse.Namespace) -> int:
    psk = None
    if args.preshared_key_stdin:
        psk = sys.stdin.readline().strip()
    peer, params, server_pub, live = add_peer(env, args.name, args.public_key, psk)
    result = {
        "schema": SCHEMA,
        "peer": peer.public_dict(),
        "server": dict(params.public_dict(), public_key=server_pub),
        "applied_live": live,
    }
    if args.json:
        emit(result)
    else:
        state = "live" if live else "written (interface down)"
        print(f"added {peer.name}: {peer.ipv4}, {peer.ipv6} [{state}]")
    return EXIT_OK


def cmd_revoke(env: Env, args: argparse.Namespace) -> int:
    peer, live = revoke_peer(env, args.name)
    if args.json:
        emit({"schema": SCHEMA, "revoked": peer.public_dict(), "applied_live": live})
    else:
        state = "removed from running interface" if live else "interface down"
        print(f"revoked {peer.name} ({peer.ipv4}) [{state}]")
    return EXIT_OK


def cmd_list(env: Env, args: argparse.Namespace) -> int:
    params = load_params(env)
    registry = load_registry(env)
    handshakes = live_handshakes(env, params)
    now = int(time.time())
    rows = []
    for peer in peers_by_address(registry.peers):
        hs = None if handshakes is None else handshakes.get(peer.public_key)
        rows.append(dict(peer.public_dict(), latest_handshake=hs, live=hs is not None))
    if args.json:
        emit({"schema": SCHEMA, "interface_up": handshakes is not None, "peers": rows})
        return EXIT_OK
    if not rows:
        print("no peers")
        return EXIT_OK
    print(f"{'NAME':<20} {'IPV4':<15} {'IPV6':<28} {'CREATED':<11} HANDSHAKE")
    for row in rows:
        hs = row["latest_handshake"]
        if handshakes is None:
            hs_text = "interface down"
        elif hs is None:
            hs_text = "NOT LIVE (run vpnctl apply)"
        elif hs == 0:
            hs_text = "never"
        else:
            hs_text = format_age(max(0, now - hs))
        print(
            f"{row['name']:<20} {row['ipv4']:<15} {row['ipv6']:<28} {row['created']:<11} {hs_text}"
        )
    return EXIT_OK


def cmd_info(env: Env, args: argparse.Namespace) -> int:
    params = load_params(env)
    server_pub = server_public_key(env, read_server_key(env))
    emit({"schema": SCHEMA, "server": dict(params.public_dict(), public_key=server_pub)})
    return EXIT_OK


def cmd_apply(env: Env, args: argparse.Namespace) -> int:
    with locked(env):
        params = load_params(env)
        registry = load_registry(env)
        live = apply_config(env, params, registry)
    print(f"applied {len(registry.peers)} peer(s)" + ("" if live else " (interface down)"))
    return EXIT_OK


def cmd_health(env: Env, args: argparse.Namespace) -> int:
    checks = health_checks(env)
    failed = any(c.status == FAIL for c in checks)
    if args.json:
        emit(
            {"schema": SCHEMA, "ok": not failed, "checks": [dataclasses.asdict(c) for c in checks]}
        )
    else:
        for c in checks:
            print(f"[{c.status}] {c.name:<22} {c.detail}")
        print("overall: " + ("FAIL" if failed else "OK"))
    return EXIT_FAILURE if failed else EXIT_OK


def cmd_backup(env: Env, args: argparse.Namespace) -> int:
    if sys.stdout.isatty():
        raise VpnctlError("refusing to write a binary archive to a terminal; redirect stdout")
    write_backup(env, sys.stdout.buffer)
    sys.stdout.buffer.flush()
    return EXIT_OK


def cmd_restore(env: Env, args: argparse.Namespace) -> int:
    registry, live = restore_backup(env, sys.stdin.buffer)
    print(
        f"restored server key and {len(registry.peers)} peer(s)"
        + ("" if live else " (interface down)"),
        file=sys.stderr,
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpnctl", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"vpnctl {VERSION}")
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=DEFAULT_CONFIG_DIR,
        help=argparse.SUPPRESS,  # for tests; production always uses /etc/wireguard
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add", help="register a peer by public key and apply live")
    p.add_argument("name")
    p.add_argument("--public-key", required=True)
    p.add_argument(
        "--preshared-key-stdin",
        action="store_true",
        help="read the peer's preshared key from the first line of stdin",
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("revoke", help="remove a peer and apply live")
    p.add_argument("name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("list", help="list peers and their latest handshake")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("info", help="print public server parameters as JSON")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("apply", help="re-render the interface config and sync it live")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("health", help="check the server is configured and working")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("backup", help="write a tar backup of server state to stdout")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("restore", help="restore server key and peers from a tar on stdin")
    p.set_defaults(func=cmd_restore)
    return parser


def main(argv: Sequence[str] | None = None, env: Env | None = None) -> int:
    args = build_parser().parse_args(argv)
    if env is None:
        env = Env(config_dir=args.config_dir)
        if args.config_dir == DEFAULT_CONFIG_DIR and os.geteuid() != 0:
            print("vpnctl: must run as root (use sudo)", file=sys.stderr)
            return EXIT_USAGE
    os.umask(0o077)
    try:
        return args.func(env, args)
    except VpnctlError as exc:
        print(f"vpnctl: {exc}", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())

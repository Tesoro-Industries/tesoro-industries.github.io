"""Shared fixtures.

No key material is committed: every key used in tests is generated at runtime
(random 32 bytes, base64), so the repository hygiene test can forbid key-shaped
strings in tracked files.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True


def load_module(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


vpnctl = load_module("vpnctl", ROOT / "server" / "vpnctl.py")
vpn_cli = load_module("vpn_cli", ROOT / "bin" / "vpn") if (ROOT / "bin" / "vpn").exists() else None

HAVE_WG = shutil.which("wg") is not None


def random_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def fake_pubkey(private_key: str) -> str:
    """Deterministic stand-in for `wg pubkey` (NOT real Curve25519)."""
    return base64.b64encode(hashlib.sha256(private_key.strip().encode()).digest()).decode()


class FakeRunner:
    """Records commands and returns canned results. Mimics vpnctl.default_runner."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail: dict[tuple[str, ...], str] = {}
        self.outputs: dict[tuple[str, ...], tuple[int, str]] = {}

    def __call__(self, cmd, *, input=None, check=True):
        cmd = list(cmd)
        self.calls.append((cmd, input))
        for prefix, message in self.fail.items():
            if tuple(cmd[: len(prefix)]) == prefix:
                if check:
                    raise vpnctl.VpnctlError(message)
                return subprocess.CompletedProcess(cmd, 1, "", message)
        for prefix, (rc, out) in self.outputs.items():
            if tuple(cmd[: len(prefix)]) == prefix:
                if check and rc != 0:
                    raise vpnctl.VpnctlError(f"{cmd[0]} failed")
                return subprocess.CompletedProcess(cmd, rc, out, "")
        if cmd[:2] == ["wg", "pubkey"]:
            return subprocess.CompletedProcess(cmd, 0, fake_pubkey(input) + "\n", "")
        if cmd[:2] == ["wg-quick", "strip"]:
            text = Path(cmd[2]).read_text()
            keep = [
                ln
                for ln in text.splitlines()
                if not ln.startswith(("Address", "SaveConfig", "#"))
            ]
            return subprocess.CompletedProcess(cmd, 0, "\n".join(keep) + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def commands(self, *prefix: str) -> list[tuple[list[str], str | None]]:
        return [c for c in self.calls if tuple(c[0][: len(prefix)]) == prefix]


def default_params(**overrides) -> dict:
    params = {
        "schema": 1,
        "interface": "wg0",
        "listen_port": 51820,
        "endpoint": "vpn.example.net",
        "ipv4_network": "10.99.0.0/24",
        "ipv6_network": "fd5b:7a13:c0e2:9f41::/64",
        "ipv6_mode": "tunnel",
        "client_keepalive": 25,
    }
    params.update(overrides)
    return params


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def env(tmp_path: Path, runner: FakeRunner):
    """A vpnctl Env rooted in a temp dir with params and a server key."""
    config = tmp_path / "etc-wireguard"
    config.mkdir(mode=0o700)
    (config / "vpnctl.json").write_text(json.dumps(default_params()))
    key = config / "server.key"
    key.write_text(random_key() + "\n")
    key.chmod(0o600)
    sysfs = tmp_path / "sys"
    (sysfs / "class" / "net").mkdir(parents=True)
    procfs = tmp_path / "proc"
    runroot = tmp_path / "run"
    runroot.mkdir()
    return vpnctl.Env(
        config_dir=config, sys_root=sysfs, proc_root=procfs, run_root=runroot, runner=runner
    )


def bring_up(env) -> None:
    (env.sys_root / "class" / "net" / "wg0").mkdir(exist_ok=True)

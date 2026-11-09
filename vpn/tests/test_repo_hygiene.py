"""Fail if any file that git would commit contains key material or real IPs.

Complements gitleaks (ADR-0008). Scans tracked files plus untracked files that
are not git-ignored, so it catches mistakes before they are committed.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess

import pytest
from conftest import ROOT

# A WireGuard key: 32 bytes base64 -> 43 chars + '=' (last char from a limited set).
WG_KEY = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=(?![A-Za-z0-9+/=])")
# Assembled from parts so this file does not match its own patterns.
PRIVATE_BLOCK = re.compile("-----BEGIN [A-Z ]*" + "PRIVATE KEY-----|AGE-SECRET" + "-KEY-1")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
DO_TOKEN = re.compile(r"\bdop_v1_[a-f0-9]{64}\b")

# Public addresses that are allowed: documented public DNS resolvers.
ALLOWED_PUBLIC_V4 = {"9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1", "8.8.8.8"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def candidate_files():
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "."],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    for rel in filter(None, out.split("\0")):
        path = ROOT / rel
        if path.is_file():
            yield rel, path


def text_of(path):
    data = path.read_bytes()
    if b"\0" in data[:1024]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def ipv4_allowed(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return True  # not an address (e.g. a version number like 1.2.3.4000)
    if not ip.is_global:
        return True  # private, loopback, unspecified, link-local, ...
    return addr in ALLOWED_PUBLIC_V4 or any(ip in n for n in DOC_NETS)


def test_no_secrets_or_real_ips_in_repository():
    problems = []
    files = list(candidate_files())
    assert files, "no files found; is this a git checkout?"
    for rel, path in files:
        text = text_of(path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if WG_KEY.search(line):
                problems.append(f"{rel}:{lineno}: WireGuard-key-shaped string")
            if PRIVATE_BLOCK.search(line):
                problems.append(f"{rel}:{lineno}: private key block")
            if DO_TOKEN.search(line):
                problems.append(f"{rel}:{lineno}: DigitalOcean token")
            for addr in IPV4.findall(line):
                if not ipv4_allowed(addr):
                    problems.append(f"{rel}:{lineno}: public IPv4 {addr}")
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    "line, bad",
    [
        ("PrivateKey = " + "A" * 42 + "E=", True),
        ("endpoint 203.0.113.9", False),
        ("endpoint " + "164.90" + ".1.2", True),
        ("dns 9.9.9.9", False),
        ("net 10.99.0.0/24", False),
    ],
)
def test_detectors(line, bad):
    found = bool(WG_KEY.search(line)) or not all(ipv4_allowed(a) for a in IPV4.findall(line))
    assert found == bad


def test_gitignore_covers_secret_locations():
    probes = [
        "local/terraform.tfstate",
        "local/peers/phone.conf",
        "local/backups/vpn.tar.age",
        ".env",
        "terraform/terraform.tfvars",
        "terraform/terraform.tfstate",
        "wg0.conf",
        "server.key",
    ]
    proc = subprocess.run(
        ["git", "check-ignore", "--no-index", *probes], cwd=ROOT, capture_output=True, text=True
    )
    ignored = set(proc.stdout.split())
    assert ignored == set(probes), f"not ignored: {set(probes) - ignored}"
    proc = subprocess.run(
        ["git", "check-ignore", "--no-index", ".env.example", "terraform/terraform.tfvars.example"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.stdout.strip() == "", "example files must not be ignored"

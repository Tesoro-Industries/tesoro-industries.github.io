"""Render the Ansible role templates with real Ansible and validate the output
with the same tools the server uses (nft -c, unbound-checkconf, sshd -t,
fail2ban-client --test). Each tool-specific test skips if the tool is absent.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, vpnctl

pytestmark = pytest.mark.skipif(
    not shutil.which("ansible-playbook"), reason="ansible-playbook not installed"
)

SCENARIOS = {
    "tunnel": {"vpn_ipv6_mode": "tunnel", "unbound_upstream_ipv6": True},
    "block": {
        "vpn_ipv6_mode": "block",
        "unbound_upstream_ipv6": False,
        "vpn_allow_peer_to_peer": True,
    },
}


def render(tmp_path: Path, scenario: dict) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    extra = tmp_path / "scenario.json"
    extra.write_text(json.dumps(dict(scenario, out_dir=str(out), vpn_wan_interface="eth0")))
    env = dict(
        os.environ, ANSIBLE_LOCALHOST_WARNING="false", ANSIBLE_INVENTORY_UNPARSED_WARNING="false"
    )
    proc = subprocess.run(
        ["ansible-playbook", "render.yml", "-e", f"@{extra}"],
        cwd=ROOT / "tests" / "ansible",
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


@pytest.fixture(scope="module", params=sorted(SCENARIOS))
def rendered(request, tmp_path_factory):
    name = request.param
    return name, render(tmp_path_factory.mktemp(name), SCENARIOS[name])


def rules(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


# --------------------------------------------------------------------------
# nftables
# --------------------------------------------------------------------------


def chain(text: str, name: str) -> list[str]:
    match = re.search(rf"chain {name} \{{(.*?)\n\t\}}", text, re.S)
    assert match, f"chain {name} not found"
    return rules(match.group(1))


def test_nftables_policy(rendered):
    mode, out = rendered
    text = (out / "nftables.conf").read_text()
    code = "\n".join(rules(text))
    assert "flush ruleset" not in code  # must not wipe fail2ban's table
    assert " log" not in code and not code.startswith("log")  # no packet logging
    inp = chain(text, "input")
    assert inp[0] == "type filter hook input priority filter; policy drop;"
    accepts = [r for r in inp if r.endswith("accept")]
    public = [
        r
        for r in accepts
        if not r.startswith(("iifname", "meta l4proto icmp", "meta l4proto ipv6-icmp", "ct state"))
    ]
    assert public == [
        'iif "lo" accept',
        "tcp dport 22 ct state new accept",
        "udp dport 51820 accept",
    ]
    dns = [r for r in inp if "dport 53" in r]
    assert dns == ["iifname $VPN meta l4proto { tcp, udp } th dport 53 accept"]

    fwd = chain(text, "forward")
    assert fwd[0] == "type filter hook forward priority filter; policy drop;"
    assert "iifname $VPN oifname $WAN ip saddr $VPN_NET4 accept" in fwd
    assert fwd[-1] == "iifname $VPN reject with icmpx type admin-prohibited"
    nat = text.split("table inet vpn_nat {", 1)[1]
    assert "oifname $WAN ip saddr $VPN_NET4 masquerade" in nat
    if mode == "tunnel":
        assert "iifname $VPN oifname $WAN ip6 saddr $VPN_NET6 accept" in fwd
        assert "oifname $WAN ip6 saddr $VPN_NET6 masquerade" in nat
        assert "iifname $VPN oifname $VPN accept" not in fwd  # no peer-to-peer by default
    else:
        assert "iifname $VPN meta nfproto ipv6 reject with icmpv6 type admin-prohibited" in fwd
        assert not any("ip6 saddr" in r and r.endswith("accept") for r in fwd)
        assert "ip6 saddr" not in nat
        assert "iifname $VPN oifname $VPN accept" in fwd


@pytest.mark.skipif(not shutil.which("nft"), reason="nft not installed")
def test_nftables_kernel_dry_run(rendered):
    """`nft -c` parses and evaluates the ruleset against the kernel without applying it."""
    _, out = rendered
    proc = subprocess.run(
        ["nft", "-c", "-f", str(out / "nftables.conf")], capture_output=True, text=True
    )
    if proc.returncode != 0 and "Operation not permitted" in proc.stderr:
        pytest.skip("nft -c needs CAP_NET_ADMIN")
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------------
# unbound
# --------------------------------------------------------------------------


def test_unbound_listens_only_on_tunnel_and_logs_nothing(rendered):
    mode, out = rendered
    text = (out / "unbound-vpn.conf").read_text()
    interfaces = re.findall(r"^\s*interface: (\S+)", text, re.M)
    assert interfaces == ["10.99.0.1", "fd5b:7a13:c0e2:9f41::1"]
    for setting in (
        "log-queries: no",
        "log-replies: no",
        "verbosity: 0",
        "forward-tls-upstream: yes",
        "access-control: 0.0.0.0/0 refuse",
        "access-control: ::/0 refuse",
        "access-control: 10.99.0.0/24 allow",
        "ip-freebind: yes",
    ):
        assert setting in text, setting
    upstreams = re.findall(r"forward-addr: (\S+)", text)
    assert all(u.endswith("@853#dns.quad9.net") for u in upstreams)
    has_v6 = any(":" in u.split("@")[0] for u in upstreams)
    assert has_v6 == (mode == "tunnel")


def test_unbound_addresses_match_vpnctl(rendered):
    """unbound must listen exactly where vpnctl tells clients the DNS server is."""
    _, out = rendered
    params = vpnctl.ServerParams.from_dict(json.loads((out / "vpnctl.json").read_text()))
    text = (out / "unbound-vpn.conf").read_text()
    assert re.findall(r"^\s*interface: (\S+)", text, re.M) == list(params.dns)


@pytest.mark.skipif(not shutil.which("unbound-checkconf"), reason="unbound not installed")
def test_unbound_checkconf(rendered):
    _, out = rendered
    proc = subprocess.run(
        ["unbound-checkconf", str(out / "unbound-vpn.conf")], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------
# sshd, fail2ban, apt, journald
# --------------------------------------------------------------------------


@pytest.mark.skipif(not shutil.which("sshd"), reason="openssh-server not installed")
def test_sshd_effective_config(rendered, tmp_path):
    _, out = rendered
    host_key = tmp_path / "hostkey"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
    cfg = tmp_path / "sshd_config"
    # Our drop-in first, then a hostile later file, exactly like 50-cloud-init.conf.
    cfg.write_text(
        (out / "sshd-hardening.conf").read_text()
        + "PasswordAuthentication yes\nPermitRootLogin yes\n"
        + f"HostKey {host_key}\n"
    )
    proc = subprocess.run(["/usr/sbin/sshd", "-T", "-f", str(cfg)], capture_output=True, text=True)
    if "privilege separation directory" in proc.stderr:
        os.makedirs("/run/sshd", exist_ok=True)
        proc = subprocess.run(
            ["/usr/sbin/sshd", "-T", "-f", str(cfg)], capture_output=True, text=True
        )
    assert proc.returncode == 0, proc.stderr
    effective = proc.stdout.splitlines()
    for line in (
        "permitrootlogin no",
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "authenticationmethods publickey",
        "allowusers wgadmin",
        "x11forwarding no",
        "allowtcpforwarding no",
        "maxauthtries 3",
    ):
        assert line in effective, line


@pytest.mark.skipif(not shutil.which("fail2ban-client"), reason="fail2ban not installed")
@pytest.mark.skipif(not Path("/etc/fail2ban/jail.conf").exists(), reason="no stock fail2ban config")
def test_fail2ban_config(rendered, tmp_path):
    _, out = rendered
    conf = tmp_path / "fail2ban"
    shutil.copytree("/etc/fail2ban", conf)
    shutil.copy(out / "jail.local", conf / "jail.d" / "zz-vpn.local")
    shutil.copy(out / "fail2ban.local", conf / "fail2ban.d" / "zz-vpn.local")
    proc = subprocess.run(
        ["fail2ban-client", "-c", str(conf), "--test"], capture_output=True, text=True
    )
    if "python3-systemd" in proc.stderr or "systemd" in proc.stderr and proc.returncode:
        pytest.skip(f"systemd backend unavailable here: {proc.stderr.strip()[:200]}")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    dump = subprocess.run(
        ["fail2ban-client", "-c", str(conf), "-d"], capture_output=True, text=True
    ).stdout
    assert "'sshd'" in dump and "nftables" in dump


def test_unattended_upgrades(rendered):
    _, out = rendered
    auto = (out / "20auto-upgrades").read_text()
    assert 'APT::Periodic::Unattended-Upgrade "1";' in auto
    assert 'APT::Periodic::Update-Package-Lists "1";' in auto
    reboot = (out / "52vpn-unattended-upgrades").read_text()
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in reboot
    assert 'Unattended-Upgrade::Automatic-Reboot-Time "04:30";' in reboot


def test_journald_bounded(rendered):
    _, out = rendered
    text = (out / "journald.conf").read_text()
    assert "MaxRetentionSec=7day" in text and "SystemMaxUse=200M" in text


# --------------------------------------------------------------------------
# Ansible -> vpnctl contract, sysctl
# --------------------------------------------------------------------------


def test_vpnctl_params_contract(rendered):
    mode, out = rendered
    data = json.loads((out / "vpnctl.json").read_text())
    params = vpnctl.ServerParams.from_dict(data)  # raises if the contract is broken
    assert params.listen_port == 51820 and isinstance(data["listen_port"], int)
    assert params.client_keepalive == 25 and isinstance(data["client_keepalive"], int)
    assert params.endpoint == "192.0.2.20"
    assert params.ipv6_mode == mode


def test_sysctl_forwarding_and_accept_ra_order(rendered):
    _, out = rendered
    settings = json.loads((out / "sysctl.json").read_text())
    names = [s["name"] for s in settings]
    values = {s["name"]: s["value"] for s in settings}
    assert values["net.ipv4.ip_forward"] == "1"
    assert values["net.ipv6.conf.all.forwarding"] == "1"
    assert values["net.ipv6.conf.eth0.accept_ra"] == "2"
    assert names.index("net.ipv6.conf.eth0.accept_ra") < names.index("net.ipv6.conf.all.forwarding")

from __future__ import annotations

import ipaddress
import json
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import HAVE_WG, ROOT, default_params, random_key, vpn_cli

V = vpn_cli.VpnError
SERVER = {
    "server_ipv4": "10.99.0.1",
    "server_ipv6": "fd5b:7a13:c0e2:9f41::1",
    "dns": ["10.99.0.1", "fd5b:7a13:c0e2:9f41::1"],
    "endpoint": "vpn.example.net",
    "listen_port": 51820,
    "public_key": "SERVERPUB",
    "client_keepalive": 25,
}
PEER = {"ipv4": "10.99.0.2", "ipv6": "fd5b:7a13:c0e2:9f41::2"}


def nets(strings):
    return [ipaddress.ip_network(s) for s in strings]


def covers(allowed, address):
    addr = ipaddress.ip_address(address)
    return any(addr in n for n in nets(allowed))


# --------------------------------------------------------------------------
# AllowedIPs (full / split tunnel)
# --------------------------------------------------------------------------


def test_full_tunnel_is_both_families():
    assert vpn_cli.compute_allowed_ips(SERVER) == ["0.0.0.0/0", "::/0"]


def test_split_tunnel_always_includes_tunnel_dns():
    allowed = vpn_cli.compute_allowed_ips(SERVER, nets(["192.168.50.0/24"]))
    assert allowed == ["10.99.0.1/32", "192.168.50.0/24", "fd5b:7a13:c0e2:9f41::1/128"]


def test_exclude_lan_from_full_tunnel():
    allowed = vpn_cli.compute_allowed_ips(SERVER, exclude=nets(["192.168.1.0/24"]))
    assert not covers(allowed, "192.168.1.20")
    for routed in ("192.168.0.1", "192.168.2.1", "8.8.8.8", "10.99.0.1", "2001:db8::1"):
        assert covers(allowed, routed), routed
    assert "::/0" in allowed  # IPv6 still fully tunnelled


def test_exclude_cannot_remove_dns_route():
    allowed = vpn_cli.compute_allowed_ips(SERVER, exclude=nets(["10.0.0.0/8", "fd00::/8"]))
    assert covers(allowed, "10.99.0.1")
    assert covers(allowed, "fd5b:7a13:c0e2:9f41::1")
    assert not covers(allowed, "10.1.2.3")


def test_exclude_everything_ipv6_keeps_only_dns():
    allowed = vpn_cli.compute_allowed_ips(SERVER, exclude=nets(["::/0"]))
    v6 = [a for a in allowed if ":" in a]
    assert v6 == ["fd5b:7a13:c0e2:9f41::1/128"]


@pytest.mark.parametrize("bad", ["10.0.0.1/8", "banana", "300.1.1.1/32"])
def test_parse_networks_rejects(bad):
    with pytest.raises(V):
        vpn_cli.parse_networks([bad], "--allowed-ips")


def test_parse_networks_accepts_comma_lists_and_repeats():
    got = vpn_cli.parse_networks(["10.0.0.0/8, 172.16.0.0/12", "192.168.0.0/16"], "x")
    assert [str(n) for n in got] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def render(**kw):
    args = dict(
        name="phone",
        private_key="PRIV",
        preshared_key="PSK",
        peer=PEER,
        server=SERVER,
        allowed_ips=["0.0.0.0/0", "::/0"],
        keepalive=25,
    )
    args.update(kw)
    return vpn_cli.render_client_config(**args)


def test_render_full_tunnel():
    text = render()
    assert "PrivateKey = PRIV" in text
    assert "Address = 10.99.0.2/32, fd5b:7a13:c0e2:9f41::2/128" in text
    assert "DNS = 10.99.0.1, fd5b:7a13:c0e2:9f41::1" in text
    assert "PublicKey = SERVERPUB" in text
    assert "PresharedKey = PSK" in text
    assert "Endpoint = vpn.example.net:51820" in text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in text
    assert "PersistentKeepalive = 25" in text
    assert "Split tunnel" not in text


def test_render_split_and_ipv6_endpoint_and_no_keepalive():
    server = dict(SERVER, endpoint="2001:db8::7")
    text = render(server=server, allowed_ips=["192.168.50.0/24"], keepalive=0)
    assert "Endpoint = [2001:db8::7]:51820" in text
    assert "Split tunnel" in text
    assert "PersistentKeepalive" not in text


def test_render_without_private_key_is_a_fragment():
    text = render(private_key=None)
    assert "PrivateKey =" not in text
    assert "keep the line your WireGuard app generated" in text


@pytest.mark.skipif(not shutil.which("wg-quick"), reason="wg-quick not installed")
def test_wg_quick_parses_rendered_client_config(tmp_path):
    keys = {k: random_key() for k in ("priv", "psk", "pub")}
    text = render(
        private_key=keys["priv"],
        preshared_key=keys["psk"],
        server=dict(SERVER, public_key=keys["pub"]),
        allowed_ips=vpn_cli.compute_allowed_ips(SERVER, exclude=nets(["192.168.1.0/24"])),
    )
    conf = tmp_path / "wg9.conf"
    conf.write_text(text)
    conf.chmod(0o600)
    out = subprocess.run(
        ["wg-quick", "strip", str(conf)], capture_output=True, text=True, check=True
    ).stdout
    assert f"PrivateKey = {keys['priv']}" in out and "DNS" not in out


# --------------------------------------------------------------------------
# SSH transport / .env
# --------------------------------------------------------------------------


def test_ssh_command_quotes_every_argument(tmp_path):
    t = vpn_cli.SshTransport(tmp_path / "ssh_config", "vpn")
    hostile = "x'; touch /tmp/pwned; echo '"
    cmd = t.command(["add", hostile, "--json"])
    assert cmd[:3] == ["ssh", "-F", str(tmp_path / "ssh_config")]
    assert "BatchMode=yes" in cmd
    assert cmd[-2] == "vpn"
    # the remote shell sees exactly our argv, no injection
    expected = ["sudo", "-n", "/usr/local/sbin/vpnctl", "add", hostile, "--json"]
    assert shlex.split(cmd[-1]) == expected


def test_ssh_transport_requires_config(tmp_path):
    with pytest.raises(V, match="make infra"):
        vpn_cli.SshTransport(tmp_path / "missing", "vpn").check()


def test_load_dotenv(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\n\nA=1\nexport B='two words'\nC=\"q\"\nEXISTING=new\nEMPTY=\n")
    environ = {"EXISTING": "old"}
    vpn_cli.load_dotenv(env_file, environ)
    assert environ == {"EXISTING": "old", "A": "1", "B": "two words", "C": "q", "EMPTY": ""}
    env_file.write_text("not a pair\n")
    with pytest.raises(V, match=":1:"):
        vpn_cli.load_dotenv(env_file, {})


def test_validate_name_matches_server_rules():
    vpnctl = sys.modules["vpnctl"]
    for name in ["phone", "a", "x" * 32, "bad name", "-x", "x" * 33, "UPPER"]:
        server_ok = bool(vpnctl.NAME_RE.match(name))
        client_ok = bool(vpn_cli.NAME_RE.match(name))
        assert server_ok == client_ok, name


# --------------------------------------------------------------------------
# End to end: bin/vpn -> (local subprocess instead of SSH) -> server/vpnctl
# --------------------------------------------------------------------------


class LocalTransport:
    """Runs the real vpnctl in a subprocess against a temp config dir."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir

    def check(self) -> None:
        pass

    def command(self, args):
        return [
            sys.executable,
            str(ROOT / "server" / "vpnctl.py"),
            "--config-dir",
            str(self.config_dir),
            *args,
        ]


@pytest.fixture
def e2e(tmp_path):
    if not HAVE_WG:
        pytest.skip("wireguard-tools not installed")
    config = tmp_path / "server"
    config.mkdir(mode=0o700)
    (config / "vpnctl.json").write_text(json.dumps(default_params()))
    key = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout
    (config / "server.key").write_text(key)
    (config / "server.key").chmod(0o600)
    paths = vpn_cli.Paths(tmp_path / "repo")
    return vpn_cli.Context(paths, LocalTransport(config)), config


def test_e2e_add_list_revoke(e2e, capsys):
    ctx, config = e2e
    assert vpn_cli.main(["peer", "add", "phone", "--no-qr"], ctx=ctx) == 0
    conf = ctx.paths.peer_conf("phone")
    text = conf.read_text()
    assert stat.S_IMODE(conf.stat().st_mode) == 0o600
    assert stat.S_IMODE(ctx.paths.peers.stat().st_mode) == 0o700

    # The client private key never reaches the server; the PSK matches on both sides.
    client_priv = text.split("PrivateKey = ")[1].split("\n")[0]
    client_psk = text.split("PresharedKey = ")[1].split("\n")[0]
    server_files = "".join(p.read_text() for p in config.iterdir() if p.is_file())
    assert client_priv not in server_files
    registry = json.loads((config / "peers.json").read_text())
    assert registry["peers"][0]["preshared_key"] == client_psk
    client_pub = subprocess.run(
        ["wg", "pubkey"], input=client_priv + "\n", capture_output=True, text=True, check=True
    ).stdout.strip()
    assert registry["peers"][0]["public_key"] == client_pub
    server_pub = subprocess.run(
        ["wg", "pubkey"],
        input=(config / "server.key").read_text(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert f"PublicKey = {server_pub}" in text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in text

    assert (
        vpn_cli.main(["peer", "add", "laptop", "--no-qr", "--exclude", "192.168.1.0/24"], ctx=ctx)
        == 0
    )
    assert "192.168.0.0/24" in ctx.paths.peer_conf("laptop").read_text()

    # Duplicate name is refused locally before contacting the server.
    assert vpn_cli.main(["peer", "add", "phone", "--no-qr"], ctx=ctx) == 1

    capsys.readouterr()
    assert vpn_cli.main(["peer", "list"], ctx=ctx) == 0
    out = capsys.readouterr().out
    assert "phone" in out and "laptop" in out and "interface down" in out

    assert vpn_cli.main(["peer", "revoke", "phone", "--yes"], ctx=ctx) == 0
    assert not conf.exists()
    assert client_pub not in (config / "wg0.conf").read_text()
    names = [p["name"] for p in json.loads((config / "peers.json").read_text())["peers"]]
    assert names == ["laptop"]


def test_e2e_public_key_flow(e2e, capsys):
    ctx, config = e2e
    device_pub = subprocess.run(
        ["wg", "pubkey"], input=random_key(), capture_output=True, text=True, check=True
    ).stdout.strip()
    assert vpn_cli.main(["peer", "add", "mac", "--public-key", device_pub], ctx=ctx) == 0
    out = capsys.readouterr().out
    assert "PrivateKey =" not in out and "Paste this" in out
    assert vpn_cli.main(["peer", "qr", "mac"], ctx=ctx) == 1  # no private key -> no QR


def test_e2e_server_errors_surface(e2e, capsys):
    ctx, _ = e2e
    assert vpn_cli.main(["peer", "revoke", "ghost", "--yes"], ctx=ctx) == 1
    assert "no such peer" in capsys.readouterr().err


def test_revoke_requires_confirmation_without_tty(e2e, monkeypatch, capsys):
    ctx, _ = e2e
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert vpn_cli.main(["peer", "revoke", "phone"], ctx=ctx) == 1
    assert "--yes" in capsys.readouterr().err


@pytest.mark.skipif(not shutil.which("age"), reason="age not installed")
def test_e2e_encrypted_backup_and_restore(e2e, tmp_path, capsys):
    ctx, config = e2e
    assert vpn_cli.main(["peer", "add", "phone", "--no-qr"], ctx=ctx) == 0
    identity = tmp_path / "identity.txt"
    subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True)
    recipient = subprocess.run(
        ["age-keygen", "-y", str(identity)], capture_output=True, text=True, check=True
    ).stdout.strip()
    original_key = (config / "server.key").read_text()
    original_peers = (config / "peers.json").read_text()

    assert vpn_cli.main(["backup", "--recipient", recipient], ctx=ctx) == 0
    (backup,) = list(ctx.paths.backups.glob("vpn-*.tar.age"))
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert b"age-encryption.org" in backup.read_bytes()[:64]
    assert original_key.strip().encode() not in backup.read_bytes()

    # Simulate a rebuilt server: fresh key, no peers.
    new_key = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout
    (config / "server.key").write_text(new_key)
    (config / "peers.json").unlink()
    assert (
        vpn_cli.main(["restore", str(backup), "--identity", str(identity), "--yes"], ctx=ctx) == 0
    )
    assert (config / "server.key").read_text() == original_key
    assert json.loads((config / "peers.json").read_text()) == json.loads(original_peers)


@pytest.mark.skipif(not shutil.which("age"), reason="age not installed")
def test_backup_requires_recipient(e2e, monkeypatch):
    ctx, _ = e2e
    monkeypatch.delenv("VPN_AGE_RECIPIENT", raising=False)
    assert vpn_cli.main(["backup"], ctx=ctx) == 1

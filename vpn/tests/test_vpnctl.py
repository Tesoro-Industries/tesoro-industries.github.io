from __future__ import annotations

import io
import ipaddress
import json
import os
import stat
import subprocess
import tarfile

import pytest
from conftest import HAVE_WG, bring_up, default_params, fake_pubkey, random_key, vpnctl

E = vpnctl.VpnctlError


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["phone", "a", "laptop-2", "x" * 32, "0"])
def test_valid_names(name):
    assert vpnctl.validate_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "Phone", "-phone", "phone-", "x" * 33, "a b", "a;rm", "a/b", "ä", "a_b", "a\nb"],
)
def test_invalid_names(name):
    with pytest.raises(E):
        vpnctl.validate_name(name)


def test_validate_key_accepts_random_key():
    key = random_key()
    assert vpnctl.validate_key(key + "\n") == key


@pytest.mark.parametrize(
    "bad",
    ["", "abc", "A" * 44, "!" * 43 + "=", random_key()[:-4] + "====", random_key()[:-1]],
)
def test_validate_key_rejects(bad):
    with pytest.raises(E):
        vpnctl.validate_key(bad)


@pytest.mark.parametrize(
    "override, message",
    [
        ({"schema": 2}, "schema"),
        ({"ipv6_mode": "ignore"}, "ipv6_mode"),
        ({"ipv4_network": "8.8.8.0/24"}, "private"),
        ({"ipv4_network": "10.0.0.0/30"}, "/29"),
        ({"ipv4_network": "10.0.0.1/24"}, "host bits"),
        ({"interface": "wg0; rm -rf /"}, "interface"),
        ({"listen_port": 0}, "listen_port"),
        ({"endpoint": "bad host!"}, "endpoint"),
        ({"dns": []}, "dns"),
    ],
)
def test_params_validation(override, message):
    with pytest.raises(E, match=message):
        vpnctl.ServerParams.from_dict(default_params(**override))


def test_params_missing_field():
    data = default_params()
    del data["endpoint"]
    with pytest.raises(E, match="missing field 'endpoint'"):
        vpnctl.ServerParams.from_dict(data)


def test_params_defaults_dns_to_tunnel_addresses():
    params = vpnctl.ServerParams.from_dict(default_params())
    assert params.dns == ("10.99.0.1", "fd5b:7a13:c0e2:9f41::1")
    assert str(params.server_ipv4) == "10.99.0.1"


def test_params_accept_ip_endpoint():
    params = vpnctl.ServerParams.from_dict(default_params(endpoint="2001:db8::1"))
    assert params.endpoint == "2001:db8::1"


# --------------------------------------------------------------------------
# Allocation
# --------------------------------------------------------------------------


def make_peer(name, offset, params):
    return vpnctl.Peer(
        name,
        random_key(),
        random_key(),
        params.ipv4_network.network_address + offset,
        params.ipv6_network.network_address + offset,
        "2026-01-01",
    )


def test_allocation_starts_after_server_and_fills_gaps():
    params = vpnctl.ServerParams.from_dict(default_params())
    reg = vpnctl.Registry()
    assert reg.allocate(params) == (
        ipaddress.IPv4Address("10.99.0.2"),
        ipaddress.IPv6Address("fd5b:7a13:c0e2:9f41::2"),
    )
    reg = vpnctl.Registry((make_peer("a", 2, params), make_peer("c", 4, params)))
    v4, v6 = reg.allocate(params)
    assert str(v4) == "10.99.0.3" and str(v6) == "fd5b:7a13:c0e2:9f41::3"


def test_allocation_exhaustion_never_uses_broadcast():
    params = vpnctl.ServerParams.from_dict(default_params(ipv4_network="10.99.0.0/29"))
    reg = vpnctl.Registry()
    allocated = []
    for i in range(5):  # .2 .. .6 ; .7 is broadcast
        v4, _ = reg.allocate(params)
        allocated.append(str(v4))
        reg = reg.with_peer(make_peer(f"p{i}", int(v4) - int(params.ipv4_network[0]), params))
    assert allocated == [f"10.99.0.{i}" for i in range(2, 7)]
    with pytest.raises(E, match="no free"):
        reg.allocate(params)


def test_registry_rejects_duplicates():
    params = vpnctl.ServerParams.from_dict(default_params())
    p = make_peer("a", 2, params)
    reg = vpnctl.Registry((p,))
    with pytest.raises(E, match="already exists"):
        reg.with_peer(make_peer("a", 3, params))
    clone = vpnctl.Peer("b", p.public_key, None, p.ipv4 + 1, p.ipv6 + 1, "2026-01-01")
    with pytest.raises(E, match="public key"):
        reg.with_peer(clone)
    with pytest.raises(E, match="duplicate"):
        vpnctl.Registry.from_dict(
            {"schema": 1, "peers": [p.to_dict(), dict(p.to_dict(), name="b")]}
        )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_render_server_config():
    params = vpnctl.ServerParams.from_dict(default_params())
    key = random_key()
    peers = (make_peer("phone", 3, params), make_peer("laptop", 2, params))
    text = vpnctl.render_server_config(params, key, vpnctl.Registry(peers))
    assert "Address = 10.99.0.1/24, fd5b:7a13:c0e2:9f41::1/64" in text
    assert "ListenPort = 51820" in text
    assert f"PrivateKey = {key}" in text
    assert "SaveConfig = false" in text
    assert "PostUp" not in text  # firewall lives in nftables, not hooks
    # sorted by address, server-side AllowedIPs are exactly the peer's /32 + /128
    assert text.index("# peer: laptop") < text.index("# peer: phone")
    assert "AllowedIPs = 10.99.0.2/32, fd5b:7a13:c0e2:9f41::2/128" in text
    assert text.count("[Peer]") == 2
    assert "0.0.0.0/0" not in text


# --------------------------------------------------------------------------
# add / revoke / apply
# --------------------------------------------------------------------------


def test_add_writes_registry_and_config_with_tight_permissions(env, runner):
    pub, psk = random_key(), random_key()
    peer, params, server_pub, live = vpnctl.add_peer(env, "phone", pub, psk)
    assert live is False  # interface down -> written, not synced
    assert not runner.commands("wg", "syncconf")
    assert str(peer.ipv4) == "10.99.0.2"
    reg = json.loads(env.registry_path.read_text())
    assert reg["peers"][0]["public_key"] == pub
    assert reg["peers"][0]["preshared_key"] == psk
    conf = env.config_dir / "wg0.conf"
    assert pub in conf.read_text()
    for path in (env.registry_path, conf):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert server_pub == fake_pubkey(env.key_path.read_text())


def test_add_syncs_live_interface(env, runner):
    bring_up(env)
    pub = random_key()
    *_, live = vpnctl.add_peer(env, "phone", pub, None)
    assert live is True
    (sync_cmd, sync_input), = runner.commands("wg", "syncconf")
    assert sync_cmd == ["wg", "syncconf", "wg0", "/dev/stdin"]
    assert pub in sync_input
    assert "Address" not in sync_input  # wg-quick strip output, not wg-quick format


def test_add_rejects_server_public_key(env):
    server_pub = fake_pubkey(env.key_path.read_text())
    with pytest.raises(E, match="server"):
        vpnctl.add_peer(env, "phone", server_pub, None)


def test_add_validates_before_touching_disk(env):
    with pytest.raises(E):
        vpnctl.add_peer(env, "Bad Name", random_key(), None)
    with pytest.raises(E):
        vpnctl.add_peer(env, "phone", "not-a-key", None)
    assert not env.registry_path.exists()


def test_revoke_removes_peer_live(env, runner):
    bring_up(env)
    keep, gone = random_key(), random_key()
    vpnctl.add_peer(env, "laptop", keep, None)
    vpnctl.add_peer(env, "phone", gone, None)
    peer, live = vpnctl.revoke_peer(env, "phone")
    assert live and peer.public_key == gone
    last_sync = runner.commands("wg", "syncconf")[-1][1]
    assert gone not in last_sync and keep in last_sync
    assert gone not in (env.config_dir / "wg0.conf").read_text()
    assert vpnctl.load_registry(env).find("phone") is None


def test_revoke_unknown_peer(env):
    with pytest.raises(E, match="no such peer"):
        vpnctl.revoke_peer(env, "ghost")


def test_address_reused_after_revoke(env):
    vpnctl.add_peer(env, "a", random_key(), None)
    vpnctl.add_peer(env, "b", random_key(), None)
    vpnctl.revoke_peer(env, "a")
    peer, *_ = vpnctl.add_peer(env, "c", random_key(), None)
    assert str(peer.ipv4) == "10.99.0.2"


def test_failed_apply_rolls_back_registry(env, runner):
    bring_up(env)
    vpnctl.add_peer(env, "laptop", random_key(), None)
    before = env.registry_path.read_text()
    runner.fail[("wg", "syncconf")] = "kernel said no"
    with pytest.raises(E, match="kernel said no"):
        vpnctl.add_peer(env, "phone", random_key(), None)
    assert env.registry_path.read_text() == before


def test_apply_refuses_peers_outside_networks(env):
    vpnctl.add_peer(env, "phone", random_key(), None)
    env.params_path.write_text(json.dumps(default_params(ipv4_network="10.50.0.0/24")))
    with pytest.raises(E, match="outside"):
        vpnctl.apply_config(env, vpnctl.load_params(env), vpnctl.load_registry(env))


def test_lock_is_exclusive(env):
    with vpnctl.locked(env):
        with pytest.raises(E, match="another vpnctl"):
            with vpnctl.locked(env, timeout=0.2):
                pass


def test_atomic_write_leaves_no_temp_files(tmp_path):
    target = tmp_path / "f"
    vpnctl.atomic_write(target, "one")
    vpnctl.atomic_write(target, "two", mode=0o640)
    assert target.read_text() == "two"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["f"]


# --------------------------------------------------------------------------
# CLI contract (consumed by bin/vpn)
# --------------------------------------------------------------------------


def run_cli(env, argv, stdin="", capsys=None, monkeypatch=None):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    rc = vpnctl.main(argv, env=env)
    out, err = capsys.readouterr()
    return rc, out, err


def test_cli_add_json_contract(env, capsys, monkeypatch):
    pub, psk = random_key(), random_key()
    rc, out, _ = run_cli(
        env,
        ["add", "phone", "--public-key", pub, "--preshared-key-stdin", "--json"],
        stdin=psk + "\n",
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    assert rc == 0
    data = json.loads(out)
    assert data["schema"] == 1
    assert set(data["peer"]) == {"name", "public_key", "ipv4", "ipv6", "created"}
    assert "preshared_key" not in out.lower().replace("preshared-key", "")  # never echoed
    assert psk not in out
    assert data["server"]["public_key"] == fake_pubkey(env.key_path.read_text())
    for field in ("endpoint", "listen_port", "dns", "server_ipv4", "server_ipv6",
                  "client_keepalive", "ipv6_mode"):
        assert field in data["server"]
    assert data["applied_live"] is False


def test_cli_errors_exit_1_without_traceback(env, capsys, monkeypatch):
    rc, _, err = run_cli(env, ["revoke", "ghost"], capsys=capsys, monkeypatch=monkeypatch)
    assert rc == 1
    assert err.startswith("vpnctl: no such peer")


def test_cli_list_reports_live_state(env, runner, capsys, monkeypatch):
    bring_up(env)
    a, b = random_key(), random_key()
    vpnctl.add_peer(env, "a", a, None)
    vpnctl.add_peer(env, "b", b, None)
    dump = "priv\tpub\t51820\toff\n" + f"{a}\t(none)\t198.51.100.7:4444\t10.99.0.2/32\t1700000000\t1\t2\t25\n"
    runner.outputs[("wg", "show", "wg0", "dump")] = (0, dump)
    rc, out, _ = run_cli(env, ["list", "--json"], capsys=capsys, monkeypatch=monkeypatch)
    data = json.loads(out)
    by_name = {p["name"]: p for p in data["peers"]}
    assert by_name["a"]["latest_handshake"] == 1700000000
    assert by_name["b"]["live"] is False
    assert "198.51.100.7" not in out  # peer endpoints (real client IPs) are never shown
    rc, out, _ = run_cli(env, ["list"], capsys=capsys, monkeypatch=monkeypatch)
    assert "NOT LIVE" in out


def test_main_requires_root_for_default_dir(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert vpnctl.main(["list"]) == 2
    assert "root" in capsys.readouterr().err


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------


def healthy(env, runner):
    bring_up(env)
    pub = random_key()
    vpnctl.add_peer(env, "phone", pub, None)
    for rel in ("sys/net/ipv4/ip_forward", "sys/net/ipv6/conf/all/forwarding"):
        f = env.proc_root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("1\n")
    runner.outputs[("wg", "show", "wg0", "listen-port")] = (0, "51820\n")
    runner.outputs[("wg", "show", "wg0", "peers")] = (0, pub + "\n")
    runner.outputs[("apt-config",)] = (0, "UU='1'\n")
    runner.outputs[("sshd", "-T")] = (0, "permitrootlogin no\npasswordauthentication no\n")
    runner.outputs[("dig", "+time=3", "+tries=1", "@10.99.0.1", "+short")] = (0, "192.0.2.1\n")
    runner.outputs[("dig",)] = (0, ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n")
    return pub


def test_health_all_pass(env, runner):
    healthy(env, runner)
    checks = vpnctl.health_checks(env)
    bad = [c for c in checks if c.status != vpnctl.PASS]
    assert bad == []
    assert len(checks) >= 15


def test_health_detects_revoked_peer_still_live(env, runner):
    healthy(env, runner)
    runner.outputs[("wg", "show", "wg0", "peers")] = (0, random_key() + "\n")
    status = {c.name: c.status for c in vpnctl.health_checks(env)}
    assert status["peers in sync"] == vpnctl.FAIL


def test_health_detects_insecure_state(env, runner):
    healthy(env, runner)
    env.key_path.chmod(0o644)
    (env.proc_root / "sys/net/ipv4/ip_forward").write_text("0\n")
    runner.outputs[("sshd", "-T")] = (0, "permitrootlogin yes\npasswordauthentication no\n")
    runner.outputs[("systemctl", "is-active", "--quiet", "fail2ban.service")] = (3, "")
    (env.run_root / "reboot-required").write_text("")
    status = {c.name: c.status for c in vpnctl.health_checks(env)}
    assert status["server key"] == vpnctl.FAIL
    assert status["ipv4 forwarding"] == vpnctl.FAIL
    assert status["sshd permitrootlogin"] == vpnctl.FAIL
    assert status["fail2ban service"] == vpnctl.FAIL
    assert status["reboot"] == vpnctl.WARN


def test_health_block_mode_skips_ipv6_forwarding(env, runner):
    healthy(env, runner)
    env.params_path.write_text(json.dumps(default_params(ipv6_mode="block")))
    names = {c.name for c in vpnctl.health_checks(env)}
    assert "ipv6 forwarding" not in names


def test_health_cli_exit_code(env, runner, capsys, monkeypatch):
    rc, out, _ = run_cli(env, ["health"], capsys=capsys, monkeypatch=monkeypatch)
    assert rc == 1 and "overall: FAIL" in out
    healthy(env, runner)
    rc, out, _ = run_cli(env, ["health", "--json"], capsys=capsys, monkeypatch=monkeypatch)
    assert rc == 0 and json.loads(out)["ok"] is True


# --------------------------------------------------------------------------
# Backup / restore
# --------------------------------------------------------------------------


def backup_bytes(env) -> bytes:
    buf = io.BytesIO()
    vpnctl.write_backup(env, buf)
    return buf.getvalue()


def test_backup_restore_round_trip(env, runner):
    vpnctl.add_peer(env, "phone", random_key(), random_key())
    vpnctl.add_peer(env, "laptop", random_key(), random_key())
    original_key = env.key_path.read_text()
    original_reg = vpnctl.load_registry(env)
    data = backup_bytes(env)

    # simulate a freshly provisioned server: new key, empty registry
    env.key_path.write_text(random_key() + "\n")
    env.registry_path.unlink()
    registry, _ = vpnctl.restore_backup(env, io.BytesIO(data))
    assert env.key_path.read_text() == original_key
    assert vpnctl.load_registry(env) == original_reg == registry
    assert original_key.strip() in (env.config_dir / "wg0.conf").read_text()
    assert stat.S_IMODE(env.key_path.stat().st_mode) == 0o600


def test_backup_members_and_permissions(env):
    data = backup_bytes(env)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        names = tar.getnames()
        assert names == ["manifest.json", "server.key", "peers.json", "vpnctl.json"]
        assert all(m.mode == 0o600 and m.uid == 0 for m in tar.getmembers())


def craft_tar(members: dict[str, bytes], symlink: str | None = None) -> io.BytesIO:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            tar.addfile(info)
    buf.seek(0)
    return buf


def valid_members(env) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(backup_bytes(env))) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers()}


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda m: m.update({"../../etc/passwd": b"x"}), "unexpected member"),
        (lambda m: m.pop("server.key"), "missing"),
        (lambda m: m.update({"manifest.json": b"{"}), "manifest"),
        (lambda m: m.update({"manifest.json": b'{"schema": 9}'}), "schema"),
        (lambda m: m.update({"server.key": b"nope"}), "server private key"),
        (lambda m: m.update({"peers.json": b"[]"}), "schema"),
    ],
)
def test_restore_rejects_bad_archives(env, mutate, message):
    members = valid_members(env)
    mutate(members)
    before = env.key_path.read_text()
    with pytest.raises(E, match=message):
        vpnctl.restore_backup(env, craft_tar(members))
    assert env.key_path.read_text() == before


def test_restore_rejects_symlink_member(env):
    members = valid_members(env)
    del members["vpnctl.json"]
    with pytest.raises(E, match="not a regular file"):
        vpnctl.restore_backup(env, craft_tar(members, symlink="vpnctl.json"))


def test_restore_rejects_garbage(env):
    with pytest.raises(E, match="not a valid archive"):
        vpnctl.restore_backup(env, io.BytesIO(b"definitely not tar" * 100))


def test_restore_rolls_back_on_apply_failure(env, runner):
    vpnctl.add_peer(env, "phone", random_key(), None)
    data = backup_bytes(env)
    current_key = random_key() + "\n"
    env.key_path.write_text(current_key)
    bring_up(env)
    runner.fail[("wg", "syncconf")] = "boom"
    with pytest.raises(E, match="boom"):
        vpnctl.restore_backup(env, io.BytesIO(data))
    assert env.key_path.read_text() == current_key


# --------------------------------------------------------------------------
# Real `wg` binary (skipped when wireguard-tools is not installed)
# --------------------------------------------------------------------------


@pytest.mark.skipif(not HAVE_WG, reason="wireguard-tools not installed")
def test_real_wg_pubkey_and_config_parse(tmp_path):
    """Use the real `wg` for key derivation and check `wg` accepts the stripped config."""
    config = tmp_path / "cfg"
    config.mkdir()
    (config / "vpnctl.json").write_text(json.dumps(default_params()))
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout
    (config / "server.key").write_text(priv)
    env = vpnctl.Env(config_dir=config, sys_root=tmp_path / "nosys")
    peer_priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout
    peer_pub = subprocess.run(
        ["wg", "pubkey"], input=peer_priv, capture_output=True, text=True, check=True
    ).stdout.strip()
    _, _, server_pub, live = vpnctl.add_peer(env, "phone", peer_pub, None)
    expected = subprocess.run(
        ["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True
    ).stdout.strip()
    assert server_pub == expected and live is False
    if __import__("shutil").which("wg-quick"):
        stripped = subprocess.run(
            ["wg-quick", "strip", str(config / "wg0.conf")],
            capture_output=True, text=True, check=True,
        ).stdout
        assert "Address" not in stripped and peer_pub in stripped

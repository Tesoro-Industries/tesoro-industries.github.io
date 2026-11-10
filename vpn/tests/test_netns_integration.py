"""Real-packet integration test in Linux network namespaces.

Builds a three-party topology on one machine:

    client ns (cli)  ──┐                         ┌── server ns (srv): eth0, wg0,
    client ns (cli2) ──┼── "internet" ns (inet) ─┤   nftables, unbound, vpnctl
                       │   router + echo server  │
                       └─────────────────────────┘

and exercises the REAL artefacts: the nftables ruleset and unbound config
rendered from the Ansible templates, `vpnctl` managing the server interface,
and client configs produced by `bin/vpn`. Traffic flows through actual
WireGuard tunnels (kernel module if present, otherwise wireguard-go).

What this does NOT cover: systemd units, Ansible itself, DigitalOcean's
network (Reserved IP), real devices, DoT to Quad9 (the resolver answers from a
local zone here). Requires root, `ip`, `wg-quick`, `nft`, `unbound`, `dig`,
`curl`, and either the wireguard kernel module or `wireguard-go`.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from conftest import ROOT, vpn_cli

REQUIRED = ["ip", "wg", "wg-quick", "nft", "unbound", "dig", "curl", "ansible-playbook"]
missing = [t for t in REQUIRED if not shutil.which(t)]
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="needs root (network namespaces)"),
    pytest.mark.skipif(bool(missing), reason=f"missing tools: {missing}"),
]

PREFIX = f"vpnt{os.getpid() % 10000}"
NS = {k: f"{PREFIX}-{k}" for k in ("inet", "srv", "cli", "cli2")}
ECHO4, ECHO6 = "198.18.0.1", "2001:db8:ff::1"  # "a website on the internet"
SRV4, SRV6 = "198.51.100.2", "2001:db8:1::2"  # server WAN (exit) addresses
CLIENT_WAN = {"cli": ("203.0.113.2", "2001:db8:2::2"), "cli2": ("192.0.2.2", "2001:db8:3::2")}
TUNNEL_DNS4, TUNNEL_DNS6 = "10.99.0.1", "fd5b:7a13:c0e2:9f41::1"
ECHO4_OTHER = "198.18.0.2"  # a second "website", used for split-tunnel checks

# Some sandboxes boot with ipv6.disable=1. The lab then runs IPv4-only and the
# IPv6 tests skip; they run wherever the kernel has IPv6 (e.g. CI runners).
HAVE_V6 = Path("/proc/sys/net/ipv6").exists()
needs_v6 = pytest.mark.skipif(not HAVE_V6, reason="kernel has IPv6 disabled")

ECHO_SERVER = textwrap.dedent(
    """
    import http.server, socket, sys
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.client_address[0].removeprefix("::ffff:").encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass
    V6 = sys.argv[2] == "6"
    class S(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6 if V6 else socket.AF_INET
        def server_bind(self):
            if V6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()
    S(("::" if V6 else "0.0.0.0", int(sys.argv[1])), H).serve_forever()
    """
)
LISTENER = textwrap.dedent(
    """
    import socket, sys
    v6 = sys.argv[2] == "6"
    s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET)
    if v6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = sys.argv[3] if len(sys.argv) > 3 else ("::" if v6 else "0.0.0.0")
    s.bind((host, int(sys.argv[1])))
    s.listen()
    while True:
        s.accept()[0].close()
    """
)


def sh(*cmd, ns=None, check=True, timeout=30, input=None):
    full = (["ip", "netns", "exec", ns] if ns else []) + [str(c) for c in cmd]
    proc = subprocess.run(
        full, capture_output=True, text=True, timeout=timeout, input=input, check=False
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"{' '.join(full)} failed ({proc.returncode}):\n{proc.stdout}{proc.stderr}"
        )
    return proc


def curl(ns, url, timeout=4):
    return sh(
        "curl", "-sS", "-g", "--max-time", timeout, url, ns=ns, check=False, timeout=timeout + 5
    )


def tcp_open(ns, host, port) -> bool:
    code = f"import socket; socket.create_connection(({host!r}, {port}), timeout=2).close()"
    return sh(sys.executable, "-c", code, ns=ns, check=False).returncode == 0


class NetnsTransport:
    """bin/vpn transport that runs vpnctl inside the server namespace."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir

    def check(self) -> None:
        pass

    def command(self, args):
        return [
            "ip", "netns", "exec", NS["srv"], sys.executable,
            str(ROOT / "server" / "vpnctl.py"), "--config-dir", str(self.config_dir), *args,
        ]  # fmt: skip


def link(a_ns, a_if, b_ns, b_if):
    sh(
        "ip",
        "link",
        "add",
        a_if,
        "netns",
        a_ns,
        "type",
        "veth",
        "peer",
        "name",
        b_if,
        "netns",
        b_ns,
    )
    sh("ip", "link", "set", a_if, "up", ns=a_ns)
    sh("ip", "link", "set", b_if, "up", ns=b_ns)


FAMILY = "6" if HAVE_V6 else "4"


def addr(ns, dev, *cidrs):
    for cidr in cidrs:
        if ":" in cidr and not HAVE_V6:
            continue
        flags = ["nodad"] if ":" in cidr else []
        sh("ip", "addr", "add", cidr, "dev", dev, *flags, ns=ns)


def render_templates(tmp: Path, mode: str) -> Path:
    from test_ansible_templates import SCENARIOS, render

    tmp.mkdir(parents=True, exist_ok=True)
    return render(tmp, dict(SCENARIOS[mode], vpn_endpoint=SRV4))


def unbound_test_config(rendered: Path, workdir: Path) -> Path:
    """Our rendered unbound config, minus the DoT upstream (no internet here),
    plus a local zone to resolve and settings to run unprivileged in a temp dir."""
    text = (rendered / "unbound-vpn.conf").read_text()
    text = text.split("forward-zone:")[0]
    if not HAVE_V6:
        text = text.replace("do-ip6: yes", "do-ip6: no")
        text = "\n".join(
            ln for ln in text.splitlines() if not ln.strip().startswith("interface: fd")
        )
        text += "\n"
    text = text.replace(
        "server:\n",
        "server:\n"
        f'    directory: "{workdir}"\n    chroot: ""\n    username: ""\n'
        f'    pidfile: "{workdir}/unbound.pid"\n    use-syslog: no\n'
        '    local-zone: "vpn.test." static\n'
        '    local-data: "probe.vpn.test. 60 IN A 192.0.2.53"\n',
        1,
    )
    path = workdir / "unbound.conf"
    path.write_text(text)
    return path


def ipv4_only(conf_text: str) -> str:
    """Drop IPv6 addresses/routes from a wg-quick config (only when the kernel lacks IPv6)."""
    out = []
    for line in conf_text.splitlines():
        key, sep, value = line.partition(" = ")
        if sep and key in ("Address", "AllowedIPs"):
            kept = [v.strip() for v in value.split(",") if ":" not in v]
            line = f"{key} = {', '.join(kept)}"
        out.append(line)
    return "\n".join(out) + "\n"


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("netns")
    procs: list[subprocess.Popen] = []
    unbound_log = None
    try:
        for ns in NS.values():
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)

        # "internet": a router with an echo server on its own addresses.
        inet = NS["inet"]
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=inet)
        if HAVE_V6:
            sh("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", ns=inet)
        addr(inet, "lo", f"{ECHO4}/32", f"{ECHO4_OTHER}/32", f"{ECHO6}/128")
        for name, (ns_key, v4, v6) in {
            "i-srv": ("srv", SRV4, SRV6),
            "i-cli": ("cli", *CLIENT_WAN["cli"]),
            "i-cli2": ("cli2", *CLIENT_WAN["cli2"]),
        }.items():
            link(NS[ns_key], "eth0", inet, name)
            gw4 = v4.rsplit(".", 1)[0] + ".1"
            gw6 = v6.rsplit("::", 1)[0] + "::1"
            addr(inet, name, f"{gw4}/24", f"{gw6}/64")
            addr(NS[ns_key], "eth0", f"{v4}/24", f"{v6}/64")
            sh("ip", "route", "add", "default", "via", gw4, ns=NS[ns_key])
            if HAVE_V6:
                sh("ip", "-6", "route", "add", "default", "via", gw6, ns=NS[ns_key])
        echo = tmp / "echo.py"
        echo.write_text(ECHO_SERVER)
        procs.append(
            subprocess.Popen(
                ["ip", "netns", "exec", inet, sys.executable, str(echo), "8080", FAMILY]
            )
        )

        # Server: sysctl + nftables + unbound (started BEFORE wg0 exists: ip-freebind) + vpnctl.
        srv = NS["srv"]
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=srv)
        if HAVE_V6:
            sh("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", ns=srv)
        rendered = render_templates(tmp / "tunnel", "tunnel")
        sh("nft", "-f", rendered / "nftables.conf", ns=srv)

        unbound_dir = tmp / "unbound"
        unbound_dir.mkdir()
        sh("unbound-checkconf", unbound_test_config(rendered, unbound_dir))
        # Ubuntu's AppArmor profile for /usr/sbin/unbound only allows its usual
        # paths (/etc/unbound, /var/lib/unbound), so it cannot read a config in
        # a temp dir. AppArmor attaches by executable path: run a copy instead.
        # (On the real server the config lives in /etc/unbound; nothing changes.)
        unbound_bin = shutil.which("unbound")
        if Path("/sys/kernel/security/apparmor").exists():
            unbound_bin = shutil.copy2(unbound_bin, unbound_dir / "unbound")
        unbound_log = open(unbound_dir / "unbound.log", "w")  # noqa: SIM115 - closed in finally
        unbound_cmd = [str(unbound_bin), "-d", "-c", str(unbound_dir / "unbound.conf")]
        unbound_proc = subprocess.Popen(
            ["ip", "netns", "exec", srv, *unbound_cmd],
            stdout=unbound_log,
            stderr=subprocess.STDOUT,
        )
        procs.append(unbound_proc)

        listener = tmp / "listen.py"
        listener.write_text(LISTENER)
        for port in ("22", "8081"):  # stand-in sshd and an unrelated service
            procs.append(
                subprocess.Popen(
                    ["ip", "netns", "exec", srv, sys.executable, str(listener), port, FAMILY]
                )
            )
        # Something listening on the WAN address at port 53, so the test proves
        # the FIREWALL (not just unbound's bind address) keeps DNS off the WAN.
        procs.append(
            subprocess.Popen(
                ["ip", "netns", "exec", srv, sys.executable, str(listener), "53", "4", SRV4]
            )
        )

        config = tmp / "etc-wireguard"
        config.mkdir(mode=0o700)
        (config / "vpnctl.json").write_text((rendered / "vpnctl.json").read_text())
        key = sh("wg", "genkey").stdout
        (config / "server.key").write_text(key)
        (config / "server.key").chmod(0o600)
        sh(sys.executable, ROOT / "server" / "vpnctl.py", "--config-dir", config, "apply", ns=srv)
        up_conf = config / "wg0.conf"
        if not HAVE_V6:  # bring the interface up from an IPv4-only copy
            up_dir = tmp / "srv-up"
            up_dir.mkdir()
            up_conf = up_dir / "wg0.conf"
            up_conf.write_text(ipv4_only((config / "wg0.conf").read_text()))
            up_conf.chmod(0o600)
        sh("wg-quick", "up", up_conf, ns=srv, timeout=60)

        ctx = vpn_cli.Context(vpn_cli.Paths(tmp / "laptop"), NetnsTransport(config))
        time.sleep(0.5)  # let unbound and the echo server finish binding
        if unbound_proc.poll() is not None:
            log = (unbound_dir / "unbound.log").read_text()
            raise AssertionError(f"unbound exited ({unbound_proc.returncode}):\n{log}")
        yield {"tmp": tmp, "config": config, "ctx": ctx, "rendered": rendered}
    finally:
        for ns in NS.values():
            pids = sh("ip", "netns", "pids", ns, check=False).stdout.split()
            for pid in pids:
                with contextlib.suppress(ProcessLookupError, ValueError):
                    os.kill(int(pid), signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for ns in NS.values():
            sh("ip", "netns", "del", ns, check=False)
        if unbound_log is not None:
            unbound_log.close()


def connect_client(lab, ns_key: str, peer: str, *extra) -> Path:
    """Add a peer with bin/vpn and bring up its config in the client namespace."""
    assert vpn_cli.main(["peer", "add", peer, "--no-qr", *extra], ctx=lab["ctx"]) == 0
    text = lab["ctx"].paths.peer_conf(peer).read_text()
    # wg-quick would call resolvconf for DNS=; the namespace has none, so DNS is
    # tested explicitly with dig against the tunnel resolver instead.
    text = "\n".join(ln for ln in text.splitlines() if not ln.startswith("DNS ="))
    if not HAVE_V6:
        text = ipv4_only(text).rstrip("\n")
    iface = f"wg{ns_key}"[:15]
    conf = lab["tmp"] / f"{iface}.conf"
    conf.write_text(text + "\n")
    conf.chmod(0o600)
    sh("wg-quick", "up", conf, ns=NS[ns_key], timeout=60)
    return conf


@pytest.fixture(scope="module")
def connected(lab):
    before = curl(NS["cli"], f"http://{ECHO4}:8080/").stdout
    assert before == CLIENT_WAN["cli"][0]  # sanity: without VPN the site sees the client
    connect_client(lab, "cli", "phone")
    connect_client(lab, "cli2", "laptop")
    return lab


# --------------------------------------------------------------------------


def test_ipv4_egress_is_natted_to_server(connected):
    assert curl(NS["cli"], f"http://{ECHO4}:8080/").stdout == SRV4


@needs_v6
def test_ipv6_egress_is_tunnelled_and_nat66(connected):
    assert curl(NS["cli"], f"http://[{ECHO6}]:8080/").stdout == SRV6


def test_handshake_visible_in_vpnctl_list(connected):
    out = sh(
        sys.executable, ROOT / "server" / "vpnctl.py", "--config-dir", connected["config"],
        "list", "--json", ns=NS["srv"],
    ).stdout  # fmt: skip
    peers = {p["name"]: p for p in json.loads(out)["peers"]}
    assert peers["phone"]["live"] and peers["phone"]["latest_handshake"] > 0


def test_dns_through_tunnel_resolver(connected):
    for server in (TUNNEL_DNS4, TUNNEL_DNS6) if HAVE_V6 else (TUNNEL_DNS4,):
        out = sh(
            "dig", "+short", "+time=2", "+tries=1", f"@{server}", "probe.vpn.test", ns=NS["cli"]
        )
        assert out.stdout.strip() == "192.0.2.53", server


def test_dns_port_firewalled_on_wan(connected):
    assert not tcp_open(NS["inet"], SRV4, 53)


def test_resolver_not_reachable_from_internet(connected):
    out = sh("dig", "+time=2", "+tries=1", f"@{SRV4}", "probe.vpn.test", ns=NS["inet"], check=False)
    assert "192.0.2.53" not in out.stdout and out.returncode != 0


def test_only_ssh_and_wireguard_reachable_from_internet(connected):
    assert tcp_open(NS["inet"], SRV4, 22)
    assert not tcp_open(NS["inet"], SRV4, 8081)
    if HAVE_V6:
        assert tcp_open(NS["inet"], SRV6, 22)
        assert not tcp_open(NS["inet"], SRV6, 8081)


def test_tunnel_clients_cannot_reach_other_server_ports(connected):
    assert not tcp_open(NS["cli"], TUNNEL_DNS4, 8081)


def test_peer_to_peer_is_blocked(connected):
    laptop_ip = re.search(
        r"Address = ([\d.]+)/32", connected["ctx"].paths.peer_conf("laptop").read_text()
    )
    proc = sh("ping", "-c", "1", "-W", "2", laptop_ip.group(1), ns=NS["cli"], check=False)
    assert proc.returncode != 0


def test_spoofed_source_from_tunnel_is_dropped(connected):
    """A peer can only send from its own AllowedIPs (WireGuard) and the tunnel
    subnet (nftables); a forged source never reaches the internet."""
    proc = sh(
        "curl", "-sS", "--max-time", "3", "--interface", CLIENT_WAN["cli"][0],
        f"http://{ECHO4}:8080/", ns=NS["cli"], check=False,
    )  # fmt: skip
    # Bound to the client's WAN address, the packet is policy-routed into the
    # tunnel (full tunnel) with a source outside AllowedIPs: dropped.
    assert proc.returncode != 0 and proc.stdout == ""


def test_revocation_is_immediate(connected):
    assert curl(NS["cli2"], f"http://{ECHO4}:8080/").stdout == SRV4
    assert vpn_cli.main(["peer", "revoke", "laptop", "--yes"], ctx=connected["ctx"]) == 0
    live = sh("wg", "show", "wg0", "peers", ns=NS["srv"]).stdout
    laptop_pub = json.loads((connected["config"] / "peers.json").read_text())
    assert len(live.split()) == len(laptop_pub["peers"]) == 1
    started = time.monotonic()
    proc = curl(NS["cli2"], f"http://{ECHO4}:8080/", timeout=3)
    assert proc.stdout != SRV4 and proc.returncode != 0
    assert time.monotonic() - started < 10
    # the remaining peer is unaffected
    assert curl(NS["cli"], f"http://{ECHO4}:8080/").stdout == SRV4


def test_split_tunnel_peer_routes_only_listed_ranges(connected):
    """--allowed-ips: only the listed range (and the DNS address) use the tunnel."""
    sh("wg-quick", "down", connected["tmp"] / "wgcli2.conf", ns=NS["cli2"], check=False)
    connect_client(connected, "cli2", "split", "--allowed-ips", f"{ECHO4}/32")
    assert curl(NS["cli2"], f"http://{ECHO4}:8080/").stdout == SRV4  # listed: via VPN
    # not listed: the other "site" sees the client's own address
    assert curl(NS["cli2"], f"http://{ECHO4_OTHER}:8080/").stdout == CLIENT_WAN["cli2"][0]
    out = sh(
        "dig", "+short", "+time=2", "+tries=1", f"@{TUNNEL_DNS4}", "probe.vpn.test", ns=NS["cli2"]
    )
    assert out.stdout.strip() == "192.0.2.53"  # DNS still reachable through the tunnel


@needs_v6
def test_ipv6_block_mode_rejects_without_leaking(connected, tmp_path):
    rendered = render_templates(tmp_path, "block")
    sh("nft", "-f", rendered / "nftables.conf", ns=NS["srv"])
    try:
        started = time.monotonic()
        proc = curl(NS["cli"], f"http://[{ECHO6}]:8080/", timeout=4)
        assert proc.returncode != 0 and proc.stdout == ""  # neither tunnelled nor leaked
        assert time.monotonic() - started < 3  # rejected fast (ICMPv6), not black-holed
        assert curl(NS["cli"], f"http://{ECHO4}:8080/").stdout == SRV4  # IPv4 unaffected
    finally:
        sh("nft", "-f", connected["rendered"] / "nftables.conf", ns=NS["srv"])
    assert curl(NS["cli"], f"http://[{ECHO6}]:8080/").stdout == SRV6


def test_nftables_reload_preserves_foreign_tables(connected):
    """Reloading our ruleset must not remove other tables (e.g. fail2ban's)."""
    sh("nft", "add", "table", "inet", "f2b-table", ns=NS["srv"])
    sh("nft", "-f", connected["rendered"] / "nftables.conf", ns=NS["srv"])
    tables = sh("nft", "list", "tables", ns=NS["srv"]).stdout
    assert "inet f2b-table" in tables and "inet vpn_filter" in tables
    sh("nft", "delete", "table", "inet", "f2b-table", ns=NS["srv"])

"""Render the Terraform templates with the real `terraform` binary (no provider needed)
and validate the results: cloud-init schema, YAML structure, ssh_config contents.

Skipped when terraform is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap

import pytest
import yaml
from conftest import ROOT

TEMPLATES = ROOT / "terraform" / "templates"
pytestmark = pytest.mark.skipif(not shutil.which("terraform"), reason="terraform not installed")

# A dummy public key shape; not a real key (repo hygiene forbids real key material).
SSH_KEY = "ssh-ed25519 " + "A" * 68 + " me@laptop: with #odd chars"


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    work = tmp_path_factory.mktemp("tf")
    (work / "main.tf").write_text(
        textwrap.dedent(
            f"""
            output "cloud_init" {{
              value = templatefile("{TEMPLATES}/cloud-init.yaml.tftpl", {{
                admin_user = "wgadmin", ssh_public_key = {json.dumps(SSH_KEY)} }})
            }}
            output "ssh_config_with_key" {{
              value = templatefile("{TEMPLATES}/ssh_config.tftpl", {{
                host_ip = "192.0.2.10", admin_user = "wgadmin",
                identity_file = "/home/me/.ssh/vpn_ed25519",
                known_hosts_file = "/repo/local/known_hosts" }})
            }}
            output "ssh_config_agent" {{
              value = templatefile("{TEMPLATES}/ssh_config.tftpl", {{
                host_ip = "192.0.2.10", admin_user = "wgadmin", identity_file = "",
                known_hosts_file = "/repo/local/known_hosts" }})
            }}
            output "inventory" {{
              value = templatefile("{TEMPLATES}/inventory.yml.tftpl", {{
                admin_user = "wgadmin", endpoint = "192.0.2.20", wireguard_port = 51820 }})
            }}
            """
        )
    )
    run = dict(cwd=work, capture_output=True, text=True, check=True)
    subprocess.run(["terraform", "init", "-input=false"], **run)
    subprocess.run(["terraform", "apply", "-auto-approve", "-input=false"], **run)
    out = subprocess.run(["terraform", "output", "-json"], **run).stdout
    return {k: v["value"] for k, v in json.loads(out).items()}, work


def test_cloud_init_structure(rendered):
    outputs, _ = rendered
    text = outputs["cloud_init"]
    assert text.startswith("#cloud-config\n")
    data = yaml.safe_load(text)
    assert data["disable_root"] is True
    assert data["ssh_pwauth"] is False
    (user,) = data["users"]  # no "default" entry -> no ubuntu user
    assert user["name"] == "wgadmin"
    assert user["lock_passwd"] is True
    assert user["ssh_authorized_keys"] == [SSH_KEY]  # quoted safely despite ': ' and '#'
    dropin = data["write_files"][0]
    assert dropin["path"] == "/etc/ssh/sshd_config.d/00-vpn-hardening.conf"
    assert "PermitRootLogin no" in dropin["content"]
    assert "PasswordAuthentication no" in dropin["content"]


@pytest.mark.skipif(not shutil.which("cloud-init"), reason="cloud-init not installed")
def test_cloud_init_schema(rendered):
    outputs, work = rendered
    path = work / "user-data.yaml"
    path.write_text(outputs["cloud_init"])
    proc = subprocess.run(["cloud-init", "schema", "-c", str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Valid schema" in proc.stdout


def test_ssh_config(rendered):
    outputs, _ = rendered
    with_key = outputs["ssh_config_with_key"]
    assert "Host vpn\n" in with_key
    assert "HostName 192.0.2.10" in with_key
    assert "IdentityFile /home/me/.ssh/vpn_ed25519" in with_key
    assert "IdentitiesOnly yes" in with_key
    assert "StrictHostKeyChecking accept-new" in with_key
    assert "UserKnownHostsFile /repo/local/known_hosts" in with_key
    assert "IdentityFile" not in outputs["ssh_config_agent"]


def test_inventory(rendered):
    outputs, _ = rendered
    data = yaml.safe_load(outputs["inventory"])
    host = data["all"]["hosts"]["vpn"]
    assert host == {
        "ansible_user": "wgadmin",
        "vpn_endpoint": "192.0.2.20",
        "vpn_listen_port": 51820,
    }

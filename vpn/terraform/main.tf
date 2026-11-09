locals {
  ssh_public_key = trimspace(file(pathexpand(var.ssh_public_key_path)))
  local_dir      = abspath("${path.module}/../local")
  everywhere     = ["0.0.0.0/0", "::/0"]
}

resource "digitalocean_ssh_key" "admin" {
  name       = "${var.name}-admin"
  public_key = local.ssh_public_key
}

resource "digitalocean_droplet" "vpn" {
  name   = var.name
  region = var.region
  size   = var.size
  image  = var.image
  ipv6   = true

  # Registering a key here stops DigitalOcean from emailing a root password and
  # enabling password login. Root SSH is then disabled by cloud-init and Ansible.
  ssh_keys = [digitalocean_ssh_key.admin.fingerprint]

  # Minimal first-boot bootstrap: create the admin user, disable root and
  # password SSH before anything else can log in (ADR-0003).
  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    admin_user     = var.admin_user
    ssh_public_key = local.ssh_public_key
  })

  # No provider agents with root on the host (ADR-0011, ADR-0012). Recovery from
  # an SSH lockout is rebuild + restore, not the web console.
  monitoring    = false
  droplet_agent = false
  backups       = false

  graceful_shutdown = true
}

# The WireGuard endpoint. A Reserved IP survives Droplet replacement, so client
# configs keep working after a rebuild + restore (ADR-0002, ADR-0009).
resource "digitalocean_reserved_ip" "endpoint" {
  region = var.region
}

resource "digitalocean_reserved_ip_assignment" "endpoint" {
  ip_address = digitalocean_reserved_ip.endpoint.ip_address
  droplet_id = digitalocean_droplet.vpn.id
}

# Provider-side firewall in front of the host's nftables ruleset (ADR-0004).
resource "digitalocean_firewall" "vpn" {
  name        = "${var.name}-fw"
  droplet_ids = [digitalocean_droplet.vpn.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_cidrs
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = tostring(var.wireguard_port)
    source_addresses = local.everywhere
  }

  # Path-MTU discovery needs ICMP "fragmentation needed" / "packet too big".
  inbound_rule {
    protocol         = "icmp"
    source_addresses = local.everywhere
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = local.everywhere
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = local.everywhere
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = local.everywhere
  }
}

# ---------------------------------------------------------------------------
# Generated connection files in local/ (git-ignored). This is the seam that
# keeps Ansible and bin/vpn provider-agnostic (ADR-0002).
# ---------------------------------------------------------------------------

resource "local_file" "ssh_config" {
  filename        = "${local.local_dir}/ssh_config"
  file_permission = "0600"
  content = templatefile("${path.module}/templates/ssh_config.tftpl", {
    host_ip          = digitalocean_droplet.vpn.ipv4_address
    admin_user       = var.admin_user
    identity_file    = var.ssh_private_key_path == "" ? "" : pathexpand(var.ssh_private_key_path)
    known_hosts_file = "${local.local_dir}/known_hosts"
  })
}

resource "local_file" "inventory" {
  filename        = "${local.local_dir}/inventory.yml"
  file_permission = "0600"
  content = templatefile("${path.module}/templates/inventory.yml.tftpl", {
    admin_user     = var.admin_user
    endpoint       = digitalocean_reserved_ip.endpoint.ip_address
    wireguard_port = var.wireguard_port
  })
}

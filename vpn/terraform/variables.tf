variable "name" {
  description = "Name for the Droplet and related resources."
  type        = string
  default     = "vpn"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,40}$", var.name))
    error_message = "name must be lowercase letters, digits and hyphens."
  }
}

variable "region" {
  description = "DigitalOcean region slug, e.g. sfo3, nyc3, ams3, fra1, lon1, sgp1, syd1. Pick the one closest to you."
  type        = string
}

variable "size" {
  description = "Droplet size slug. s-1vcpu-1gb is enough for a handful of personal devices."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "image" {
  description = "Droplet image. The Ansible roles assert Ubuntu 24.04 (ADR-0002)."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "admin_user" {
  description = "Non-root admin user created at first boot. Must not be root or ubuntu."
  type        = string
  default     = "wgadmin"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.admin_user)) && !contains(["root", "ubuntu"], var.admin_user)
    error_message = "admin_user must be a valid, non-default username (not root or ubuntu)."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key that will be authorised for admin_user."
  type        = string
}

variable "ssh_private_key_path" {
  description = "Optional path to the matching private key, written as IdentityFile into local/ssh_config. Leave empty to use your ssh-agent / default keys."
  type        = string
  default     = ""
}

variable "ssh_allowed_cidrs" {
  description = "Source ranges allowed to reach SSH (tcp/22) at the provider firewall. Narrow this to your home/office ranges if they are stable."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]

  validation {
    condition     = length(var.ssh_allowed_cidrs) > 0 && alltrue([for c in var.ssh_allowed_cidrs : can(cidrhost(c, 0))])
    error_message = "ssh_allowed_cidrs must be a non-empty list of CIDR ranges."
  }
}

variable "wireguard_port" {
  description = "UDP port WireGuard listens on. Must match vpn_listen_port in Ansible."
  type        = number
  default     = 51820

  validation {
    condition     = var.wireguard_port >= 1 && var.wireguard_port <= 65535 && floor(var.wireguard_port) == var.wireguard_port
    error_message = "wireguard_port must be an integer between 1 and 65535."
  }
}

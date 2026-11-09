output "endpoint_ip" {
  description = "Reserved IPv4 that clients connect to (WireGuard Endpoint)."
  value       = digitalocean_reserved_ip.endpoint.ip_address
}

output "exit_ipv4" {
  description = "Droplet public IPv4. Websites see this address when you browse through the VPN."
  value       = digitalocean_droplet.vpn.ipv4_address
}

output "exit_ipv6" {
  description = "Droplet public IPv6. Websites see this address over IPv6 (tunnel mode)."
  value       = digitalocean_droplet.vpn.ipv6_address
}

output "ssh" {
  description = "How to SSH to the server."
  value       = "ssh -F ${local_file.ssh_config.filename} vpn"
}

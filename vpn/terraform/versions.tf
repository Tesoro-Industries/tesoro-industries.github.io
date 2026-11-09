terraform {
  required_version = ">= 1.6.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }

  # State contains the server's IP addresses, so it lives in the git-ignored
  # local/ directory (ADR-0008). Paths are relative to this directory.
  backend "local" {
    path = "../local/terraform.tfstate"
  }
}

# Authenticates with the DIGITALOCEAN_TOKEN environment variable (from .env).
provider "digitalocean" {}

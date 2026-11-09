# Personal WireGuard VPN - single entry point. Run `make help`.
#
# Secrets come from .env (git-ignored; copy .env.example). Values must not be
# quoted: make passes them through literally.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
LOCAL := $(ROOT)/local
VENV := $(ROOT)/.venv
export PATH := $(VENV)/bin:$(PATH)

-include $(ROOT)/.env
export DIGITALOCEAN_TOKEN VPN_AGE_RECIPIENT VPN_AGE_IDENTITY

TF := terraform -chdir=$(ROOT)/terraform
ANSIBLE := cd $(ROOT)/ansible && ansible-playbook site.yml
NEED_TOKEN = @test -n "$(DIGITALOCEAN_TOKEN)" || { echo "DIGITALOCEAN_TOKEN is not set (.env)"; exit 1; }

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z0-9-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --- setup -----------------------------------------------------------------

.PHONY: tools
tools: ## Check that the required laptop tools are installed
	@missing=0; for t in python3 terraform ssh wg qrencode age; do \
	  if command -v $$t >/dev/null; then printf '  ok       %s\n' "$$t"; \
	  else printf '  MISSING  %s\n' "$$t"; missing=1; fi; done; \
	[ $$missing -eq 0 ] || { echo "See README 'Prerequisites'."; exit 1; }

.PHONY: init
init: tools ## Create local/, the Python tool venv, and initialise Terraform
	@test -f $(ROOT)/.env || { echo "Create .env from .env.example first."; exit 1; }
	@test -f $(ROOT)/terraform/terraform.tfvars || \
	  { echo "Create terraform/terraform.tfvars from terraform.tfvars.example first."; exit 1; }
	install -d -m 0700 $(LOCAL) $(LOCAL)/peers $(LOCAL)/backups
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --upgrade pip
	$(VENV)/bin/pip install --quiet -r $(ROOT)/requirements-dev.txt
	cd $(ROOT)/ansible && ansible-galaxy collection install -r requirements.yml -p collections
	$(TF) init

# --- provisioning ----------------------------------------------------------

.PHONY: plan
plan: ## Show the infrastructure changes Terraform would make
	$(NEED_TOKEN)
	$(TF) plan

.PHONY: infra
infra: ## Create/update the Droplet, firewall and reserved IP (idempotent)
	$(NEED_TOKEN)
	$(TF) apply

.PHONY: wait-ssh
wait-ssh: ## Wait until a fresh server accepts SSH and cloud-init is done
	@for i in $$(seq 1 30); do \
	  if ssh -F $(LOCAL)/ssh_config -o BatchMode=yes -o ConnectTimeout=5 vpn \
	       'cloud-init status --wait >/dev/null || true' 2>/dev/null; then exit 0; fi; \
	  echo "waiting for ssh ($$i/30)..."; sleep 10; done; \
	echo "SSH did not come up; see README Troubleshooting."; exit 1

.PHONY: configure
configure: ## Configure the server with Ansible (idempotent; safe to re-run)
	$(ANSIBLE)

.PHONY: check
check: ## Dry-run Ansible and show what would change
	$(ANSIBLE) --check --diff

.PHONY: up
up: ## From nothing to a working VPN: infra, wait for SSH, configure
	$(MAKE) infra
	$(MAKE) wait-ssh
	$(MAKE) configure

.PHONY: ssh
ssh: ## Open an SSH session to the server
	ssh -F $(LOCAL)/ssh_config vpn

# --- operations ------------------------------------------------------------

.PHONY: health
health: ## Run the server health check
	$(ROOT)/bin/vpn health

.PHONY: backup
backup: ## Encrypted backup of server key + peers to local/backups/
	$(ROOT)/bin/vpn backup

.PHONY: destroy
destroy: ## Tear down all cloud resources (asks for confirmation)
	@echo "This destroys the Droplet AND releases the Reserved IP: every client"
	@echo "config stops working. Take a backup first: make backup"
	@read -r -p "Type 'destroy' to continue: " answer; [ "$$answer" = destroy ]
	$(NEED_TOKEN)
	$(TF) destroy
	rm -f -- "$(LOCAL)/ssh_config" "$(LOCAL)/inventory.yml" "$(LOCAL)/known_hosts"
	@echo "Done. local/peers, local/backups and the Terraform state were kept."

# --- quality ---------------------------------------------------------------

.PHONY: lint
lint: ## Run all linters
	$(ROOT)/scripts/lint.sh

.PHONY: test
test: ## Run the unprivileged test suite
	cd $(ROOT) && python3 -m pytest

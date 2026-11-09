#!/usr/bin/env bash
# Run every linter for the project. Usage: scripts/lint.sh
# LINT_STRICT=1 (CI) turns a missing tool into a failure instead of a skip.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

strict="${LINT_STRICT:-0}"
failed=()
skipped=()

have() { command -v "$1" >/dev/null 2>&1; }

step() {
  local name="$1" tool="$2"
  shift 2
  if ! have "$tool"; then
    if [[ "$strict" == "1" ]]; then
      echo "FAIL  $name ($tool not installed)"
      failed+=("$name")
    else
      echo "SKIP  $name ($tool not installed)"
      skipped+=("$name")
    fi
    return 0
  fi
  if "$@" >/tmp/vpn-lint.$$.log 2>&1; then
    echo "PASS  $name"
  else
    echo "FAIL  $name"
    sed 's/^/      /' /tmp/vpn-lint.$$.log
    failed+=("$name")
  fi
  rm -f /tmp/vpn-lint.$$.log
}

mapfile -t shell_files < <(git ls-files --cached --others --exclude-standard -- '*.sh')

step "shellcheck" shellcheck shellcheck --severity=style "${shell_files[@]}"
step "ruff check" ruff ruff check .
step "ruff format" ruff ruff format --check .
step "yamllint" yamllint yamllint --strict .
step "ansible syntax" ansible-playbook \
  bash -c 'cd ansible && ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i vpn, --syntax-check site.yml'
step "ansible-lint" ansible-lint bash -c 'cd ansible && ansible-lint --strict'
step "terraform fmt" terraform terraform fmt -check -recursive terraform
step "tflint" tflint bash -c 'cd terraform && tflint --init >/dev/null && tflint --format compact'
if [[ -d terraform/.terraform ]]; then
  step "terraform validate" terraform terraform -chdir=terraform validate -no-color
else
  echo "SKIP  terraform validate (run 'terraform -chdir=terraform init -backend=false' first)"
  skipped+=("terraform validate")
fi
step "gitleaks" gitleaks gitleaks dir --no-banner --redact --config .gitleaks.toml .

echo
if ((${#skipped[@]})); then echo "skipped: ${skipped[*]}"; fi
if ((${#failed[@]})); then
  echo "lint FAILED: ${failed[*]}"
  exit 1
fi
echo "lint OK"

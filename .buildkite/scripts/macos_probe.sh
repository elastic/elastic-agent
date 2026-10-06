#!/usr/bin/env bash
# Spike (observability-robots#5246): report what an Orka macOS VM offers, nothing else.
set -uo pipefail

section() { echo "~~~ $*"; }

section "OS / hardware"
sw_vers
uname -m
sysctl -n machdep.cpu.brand_string 2>/dev/null || true
sysctl -n kern.hv_vmm_present 2>/dev/null || true

section "Privileges"
whoami
sudo -n true && echo "passwordless sudo: yes" || echo "passwordless sudo: no"

section "Tools"
for tool in git go mage asdf brew vault jq curl python3 docker colima limactl osqueryd; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "$tool: $(command -v "$tool")"
  else
    echo "$tool: missing"
  fi
done

section "Docker / virtualization"
docker version 2>&1 | head -5 || true
sysctl -n kern.hv_support 2>/dev/null || true

section "Resources"
sysctl -n hw.ncpu hw.memsize
df -h / | tail -1

section "Network"
curl -sS -o /dev/null -w "github.com: %{http_code} in %{time_total}s\n" https://github.com || true

section "Toolchain install time (asdf + go from .go-version)"
if [ -f .buildkite/scripts/macos_install_asdf.sh ]; then
  start=$(date +%s)
  source .buildkite/scripts/macos_install_asdf.sh && echo "toolchain ok"
  echo "toolchain install seconds: $(( $(date +%s) - start ))"
else
  echo "macos_install_asdf.sh not on this branch yet, skipped"
fi

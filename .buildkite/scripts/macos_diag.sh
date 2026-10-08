#!/usr/bin/env bash
# Read-only diagnostics for the macOS integration test failures (observability-robots#5246):
# launchd log file modes and the agent key in the System keychain (-25300 / fleet.enc decode).
# Installs the darwin/arm64 package built by packaging-darwin-arm64, no Fleet enrollment.
set -uo pipefail

OUT="build/macos-diag.txt"
mkdir -p build
exec > >(tee "${OUT}") 2>&1

section() { echo; echo "##### $*"; }
run() { echo "\$ $*"; "$@" 2>&1 | sed 's/^/    /'; echo "    (exit ${PIPESTATUS[0]})"; }

section "Package"
buildkite-agent artifact download "build/distributions/elastic-agent-*-darwin-aarch64.tar.gz" . --step packaging-darwin-arm64
PKG=$(ls build/distributions/elastic-agent-*-darwin-aarch64.tar.gz | grep -v core | head -1)
WORK=$(mktemp -d)
tar -xzf "${PKG}" -C "${WORK}"
AGENT_SRC=$(ls -d "${WORK}"/elastic-agent-*-darwin-aarch64)
echo "agent: ${AGENT_SRC}"

section "Environment"
run id
run sw_vers
run sudo sh -c 'umask; echo HOME=$HOME; id'
run sudo -H sh -c 'echo HOME=$HOME'
run security list-keychains -d system
run security default-keychain -d system
run ls -l /Library/Keychains/

keychain_items() {
  # only attributes, never the secret
  security dump-keychain /Library/Keychains/System.keychain 2>&1 | grep -iE -B3 -A6 'elastic' | sed 's/^/    /' || echo "    (no elastic items)"
}
agent_state() {
  run ls -lan /Library/Elastic/Agent
  run sudo stat -f '%Sp %Su:%Sg %N' /Library/Elastic/Agent/co.elastic.elastic-agent.err.log /Library/Elastic/Agent/co.elastic.elastic-agent.out.log /Library/Elastic/Agent/data/fleet.enc
  run sudo launchctl print system/co.elastic.elastic-agent
  echo "keychain items:"; keychain_items
}

section "Before install"
echo "keychain items:"; keychain_items

for round in 1 2; do
  section "Round ${round}: install"
  run sudo "${AGENT_SRC}/elastic-agent" install --force --non-interactive
  sleep 20
  agent_state

  section "Round ${round}: status/inspect, sudo variants"
  run sudo /Library/Elastic/Agent/elastic-agent status
  run sudo /Library/Elastic/Agent/elastic-agent inspect
  run sudo -H /Library/Elastic/Agent/elastic-agent inspect
  run sudo env HOME=/var/root /Library/Elastic/Agent/elastic-agent inspect
  run sudo env HOME=/Users/admin /Library/Elastic/Agent/elastic-agent inspect
  run sudo -E env "HOME=${HOME}" /Library/Elastic/Agent/elastic-agent inspect

  section "Round ${round}: uninstall"
  run sudo /Library/Elastic/Agent/elastic-agent uninstall --force
  echo "keychain items after uninstall:"; keychain_items
  run ls -la /Library/Elastic
done

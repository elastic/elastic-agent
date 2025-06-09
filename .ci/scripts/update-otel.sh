#!/bin/bash

set -euo pipefail

usage() {
  echo "Usage: $0 <next-beta-core> <next-stable-core> [<next-contrib>]"
  echo "  <next-beta-core>: Next version of the unstable core components (e.g. v0.120.0). Get it from https://github.com/open-telemetry/opentelemetry-collector/releases."
  echo "  <next-stable-core>: Next stable version of the stable core components (e.g. v1.26.0). Get it from https://github.com/open-telemetry/opentelemetry-collector/releases."
  echo "  <next-contrib>: Next version of the contrib components (e.g. v0.120.1). Get it from https://github.com/open-telemetry/opentelemetry-collector-contrib/releases. If not specified, <next-beta-core> is used."
  echo
  exit 1
}
next_beta_core=${1:-}
[[ -n "$next_beta_core" ]] || (echo "Error: missing <next-beta-core>" && echo && usage)

next_stable_core=${2:-}
[[ -n "$next_stable_core" ]] || (echo "Error: missing <next-stable-core>" && echo && usage)

next_contrib=${3:-$next_beta_core}

# Get current versions from go.mod
current_beta_core=$(grep 'go\.opentelemetry\.io/collector/receiver/otlpreceiver ' go.mod | cut -d' ' -f 2 || true)
current_stable_core=$(grep 'go\.opentelemetry\.io/collector/confmap/provider/fileprovider ' go.mod | cut -d' ' -f 2 || true)
current_contrib=$(grep 'github\.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver ' go.mod | cut -d' ' -f 2 || true)

[[ -n "$current_beta_core" ]] || (echo "Error: couldn't find current beta core version." && exit 2)
[[ -n "$current_stable_core" ]] || (echo "Error: couldn't find current stable core version" && exit 3)
[[ -n "$current_contrib" ]] || (echo "Error: couldn't find current contrib version" && exit 4)

echo "=> Updating core from $current_beta_core/$current_stable_core to $next_beta_core/$next_stable_core"
echo "=> Updating contrib from $current_contrib to $next_contrib"

sed -i.bak "s/\(go\.opentelemetry\.io\/collector.*\) $current_beta_core/\1 $next_beta_core/" go.mod
sed -i.bak "s/\(go\.opentelemetry\.io\/collector.*\) $current_stable_core/\1 $next_stable_core/" go.mod
sed -i.bak "s/\(github\.com\/open-telemetry\/opentelemetry\-collector\-contrib\/.*\) $current_contrib/\1 $next_contrib/" go.mod
rm go.mod.bak

echo "=> Running go mod tidy"
go mod tidy
echo "=> Running mage notice"
mage notice
echo "=> Running mage otel:readme"
mage otel:readme

echo "=> Creating changelog fragment"
changelog_fragment_name="update-otel-components-to-$next_contrib"
if command -v elastic-agent-changelog-tool &>/dev/null; then
  echo "=> Using elastic-agent-changelog-tool to create changelog fragment"
else
  echo "=> elastic-agent-changelog-tool not found, installing it"
  go install github.com/elastic/elastic-agent-changelog-tool@latest
fi
elastic-agent-changelog-tool new "$changelog_fragment_name"
sed -i.bak "s/^kind:.*$/kind: enhancement/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
sed -i.bak "s/^summary:.*$/summary: Update OTel components to ${next_contrib}/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
sed -i.bak "s/^component:.*$/component: elastic-agent/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
rm ./changelog/fragments/*-"${changelog_fragment_name}".yaml.bak

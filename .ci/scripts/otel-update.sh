#!/bin/bash

set -euo pipefail

usage() {
  echo "Usage: $0 <next-beta-core> <next-stable-core> [<next-contrib>]"
  echo "  <next-beta-core>: Next beta version of the core component (e.g. v0.120.0)"
  echo "  <next-stable-core>: Next stable version of the core component (e.g. v1.26.0)"
  echo "  <next-contrib>: Next beta version of the contrib component (e.g. v0.120.1). If not specified, <next-beta-core> is used."
  echo
  exit 1
}
next_beta_core=${1:-}
[[ -n "$next_beta_core" ]] || (echo "Error: missing <next-beta-core>" && echo && usage)

next_stable_core=${2:-}
[[ -n "$next_stable_core" ]] || (echo "Error: missing <next-stable-core>" && echo && usage)

next_contrib=${3:-$next_beta_core}

# Get current versions from go.mod
current_beta_core=$(grep 'go\.opentelemetry\.io/collector/receiver/otlpreceiver ' go.mod | cut -d' ' -f 2)
current_stable_core=$(grep 'go\.opentelemetry\.io/collector/confmap/provider/fileprovider ' go.mod | cut -d' ' -f 2)
current_contrib=$(grep 'github\.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver ' go.mod | cut -d' ' -f 2)

echo "=> Updating core from $current_beta_core/$current_stable_core to $next_beta_core/$next_stable_core"
echo "=> Updating contrib from $current_contrib to $next_contrib"

if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  sed_command="sed -i ''"
else
  # Linux
  sed_command="sed -i"
fi

$sed_command "s/\(go\.opentelemetry\.io\/collector.*\) $current_beta_core/\1 $next_beta_core/" go.mod
$sed_command "s/\(go\.opentelemetry\.io\/collector.*\) $current_stable_core/\1 $next_stable_core/" go.mod
$sed_command "s/\(github\.com\/open-telemetry\/opentelemetry\-collector\-contrib\/.*\) $current_contrib/\1 $next_contrib/" go.mod

echo "=> Running go mod tidy"
go mod tidy
echo "=> Running mage notice"
mage notice
echo "=> Running mage otel:readme"
mage otel:readme

echo "=> Creating changelog fragment"
changelog_fragment_name="update-otel-components-to-$next_contrib"
elastic-agent-changelog-tool new "$changelog_fragment_name"
$sed_command "s/^kind:.*$/kind: enhancement/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
$sed_command "s/^summary:.*$/summary: Update OTel components to ${next_contrib}/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
$sed_command "s/^component:.*$/component: elastic-agent/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml

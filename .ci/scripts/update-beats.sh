#!/usr/bin/env bash
#
# This script is executed by the automation we are putting in place
# and it requires the git add/commit commands.
#
set -euo pipefail
TARGET_VERSION="${1:?Error: Please provide the target version to update to}"

# Capture the OTel collector version currently required by beats so we can
# detect whether the beats bump pulls in a newer version.
otel_version_before=$(grep -v '=>' beats/go.mod | grep 'go\.opentelemetry\.io/collector/service ' | awk '{print $2}' || true)

echo "~~~ Updating to elastic/beats@${TARGET_VERSION}"
mage update:beats "$(git branch --show-current)" "${TARGET_VERSION}"

# After the beats submodule is updated, read the OTel versions it now requires.
otel_beta_core=$(grep -v '=>' beats/go.mod | grep 'go\.opentelemetry\.io/collector/service ' | awk '{print $2}' || true)
otel_stable_core=$(grep -v '=>' beats/go.mod | grep 'go\.opentelemetry\.io/collector/pdata ' | awk '{print $2}' || true)
otel_contrib=$(grep -v '=>' beats/go.mod | grep 'github\.com/open-telemetry/opentelemetry-collector-contrib/' | head -1 | awk '{print $2}' || true)

if [[ -z "$otel_beta_core" || -z "$otel_stable_core" ]]; then
  echo "Warning: could not determine OTel collector versions from beats/go.mod; skipping OTel alignment"
elif [[ "$otel_beta_core" != "$otel_version_before" ]]; then
  echo "~~~ OTel collector version changed ($otel_version_before -> $otel_beta_core), running update-otel"
  "$(dirname "$0")/update-otel.sh" "$otel_beta_core" "$otel_stable_core" "${otel_contrib:-$otel_beta_core}"
fi

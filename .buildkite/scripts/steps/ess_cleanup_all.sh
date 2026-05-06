#!/usr/bin/env bash
set -euo pipefail

# This script performs comprehensive ESS cluster cleanup:
# 1. Cleans up the shared cluster (from integration-ess step)
# 2. Cleans up any retry clusters that may have been orphaned

source .buildkite/scripts/steps/ess_oblt-cli.sh

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi
export METADATA_PREFIX

echo "~~~ Phase 1: Cleaning up shared cluster"
ess_down

echo ""
echo "~~~ Phase 2: Cleaning up retry clusters"

# Get list of all retry cluster metadata keys
retry_clusters=$(buildkite-agent meta-data keys 2>/dev/null | grep "^${METADATA_PREFIX}retry-cluster-" || true)

if [ -z "$retry_clusters" ]; then
  echo "No retry clusters found to clean up."
  exit 0
fi

cleanup_count=0
failed_count=0

while IFS= read -r metadata_key; do
  if [ -z "$metadata_key" ]; then
    continue
  fi

  cluster_name=$(buildkite-agent meta-data get "$metadata_key" 2>/dev/null || true)

  if [ -z "$cluster_name" ]; then
    echo "Warning: Empty cluster name for metadata key '$metadata_key'"
    continue
  fi

  echo "Destroying retry cluster: $cluster_name (from $metadata_key)"

  if oblt-cli cluster destroy --cluster-name "${cluster_name}" --force; then
    echo "✓ Successfully destroyed cluster: $cluster_name"
    ((cleanup_count++))
  else
    echo "✗ Failed to destroy cluster: $cluster_name (will auto-expire)"
    ((failed_count++))
  fi
done <<< "$retry_clusters"

echo ""
echo "~~~ Cleanup summary"
echo "  Retry clusters destroyed: $cleanup_count"
echo "  Retry clusters failed: $failed_count"

if [ $cleanup_count -gt 0 ]; then
  echo "Successfully cleaned up $cleanup_count retry cluster(s)"
fi

# Exit 0 even if some cleanups failed - ephemeral clusters will auto-expire
exit 0

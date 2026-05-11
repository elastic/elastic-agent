#!/usr/bin/env bash

set -euo pipefail

# This script determines which Kubernetes test tier to run and uploads the appropriate pipeline.
#
# Test Tiers:
# - Tier 1: Min/max K8s versions, basic container image only
# - Tier 2: Min/max K8s versions, all container images
# - Tier 3: All K8s versions, all container images
#
# Logic:
# - For PRs:
#   - Tier 1 by default
#   - Tier 2 if packaging files are modified
# - For branch builds (non-PR):
#   - Tier 2 on each commit
#   - Tier 3 on scheduled builds (env var K8S_SCHEDULED_TIER3=true)

# K8s versions - sync with .buildkite/bk.integration.pipeline.yml
K8S_MIN_VERSION="v1.27.16"
K8S_MAX_VERSION="v1.34.0"
K8S_ALL_VERSIONS='["v1.27.16","v1.28.15","v1.29.14","v1.30.0","v1.31.0","v1.32.0","v1.33.0","v1.34.0"]'

# Container variants
BASIC_VARIANT='["basic"]'
ALL_VARIANTS='["basic","slim","complete","service","elastic-otel-collector","wolfi","slim-wolfi","complete-wolfi","elastic-otel-collector-wolfi"]'

# Packaging-related files that trigger Tier 2 testing
PACKAGING_FILES=(
  ".buildkite/"
  "magefile.go"
  "dev-tools/"
  "go.mod"
  "go.sum"
)

# Function to check if packaging files were modified in a PR
check_packaging_files_modified() {
  if [[ -z "${BUILDKITE_PULL_REQUEST:-}" ]] || [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
    return 1
  fi

  echo "Checking for packaging file changes in PR..."

  # Get the base branch (usually main)
  BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-main}"

  # Fetch the base branch
  git fetch origin "${BASE_BRANCH}" --depth=100

  # Get list of changed files
  CHANGED_FILES=$(git diff --name-only "origin/${BASE_BRANCH}...HEAD" || true)

  if [[ -z "${CHANGED_FILES}" ]]; then
    echo "No changed files detected"
    return 1
  fi

  echo "Changed files:"
  echo "${CHANGED_FILES}"

  # Check if any packaging files were modified
  for pattern in "${PACKAGING_FILES[@]}"; do
    if echo "${CHANGED_FILES}" | grep -q "^${pattern}"; then
      echo "Packaging files modified (matched: ${pattern})"
      return 0
    fi
  done

  echo "No packaging files modified"
  return 1
}

# Determine test tier
determine_tier() {
  # Check if this is a scheduled Tier 3 run
  if [[ "${K8S_SCHEDULED_TIER3:-false}" == "true" ]]; then
    echo "tier3"
    return
  fi

  # Check if this is a PR build
  if [[ -n "${BUILDKITE_PULL_REQUEST:-}" ]] && [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
    # PR build
    if check_packaging_files_modified; then
      echo "tier2"
    else
      echo "tier1"
    fi
  else
    # Branch build (non-PR) - always Tier 2
    echo "tier2"
  fi
}

# Generate matrix configuration based on tier
generate_matrix() {
  local tier=$1
  local versions
  local variants

  case "${tier}" in
    tier1)
      echo "Using Tier 1: Min/max K8s versions, basic container image"
      versions="[\"${K8S_MIN_VERSION}\",\"${K8S_MAX_VERSION}\"]"
      variants="${BASIC_VARIANT}"
      ;;
    tier2)
      echo "Using Tier 2: Min/max K8s versions, all container images"
      versions="[\"${K8S_MIN_VERSION}\",\"${K8S_MAX_VERSION}\"]"
      variants="${ALL_VARIANTS}"
      ;;
    tier3)
      echo "Using Tier 3: All K8s versions, all container images"
      versions="${K8S_ALL_VERSIONS}"
      variants="${ALL_VARIANTS}"
      ;;
    *)
      echo "ERROR: Unknown tier: ${tier}"
      exit 1
      ;;
  esac

  # Create matrix combining versions and variants
  cat <<EOF
{
  "setup": {
    "version": ${versions},
    "variant": ${variants}
  }
}
EOF
}

# Main
main() {
  echo "Determining Kubernetes test tier..."

  K8S_TEST_TIER=$(determine_tier)
  echo "Selected tier: ${K8S_TEST_TIER}"

  K8S_TEST_MATRIX=$(generate_matrix "${K8S_TEST_TIER}")
  echo "Generated matrix:"
  echo "${K8S_TEST_MATRIX}"
  export K8S_TEST_TIER K8S_TEST_MATRIX

  # Export matrix for pipeline
  export K8S_TEST_TIER K8S_TEST_MATRIX

  # Upload the k8s pipeline
  echo "Uploading Kubernetes test pipeline..."
  buildkite-agent pipeline upload .buildkite/k8s-testing-pipeline.yml
}

main "$@"

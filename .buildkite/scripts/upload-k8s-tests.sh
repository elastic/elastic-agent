#!/usr/bin/env bash

set -euo pipefail

# This script determines which Kubernetes test tier to run and uploads the appropriate pipeline.
#
# Test Tiers:
# - Tier 1: Min/max K8s versions, complete* container images only
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

IMAGE_UBUNTU_2404_X86_64=${IMAGE_UBUNTU_2404_X86_64:?"environment variable missing."}

# K8s versions
K8S_MIN_VERSION="v1.27.16"
K8S_MAX_VERSION="v1.34.0"
ALL_VERSIONS='["v1.27.16", "v1.28.15", "v1.29.14", "v1.30.0", "v1.31.0", "v1.32.0", "v1.33.0", "v1.34.0"]'

DEFAULT_VARIANT='["complete", "complete-wolfi"]'
ALL_VARIANTS='["basic", "slim", "complete", "service", "elastic-otel-collector", "wolfi", "slim-wolfi", "complete-wolfi", "elastic-otel-collector-wolfi"]'

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

  echo "Checking for packaging file changes in PR..." >&2

  # Get the base branch (usually main)
  BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-main}"

  # Fetch the base branch
  git fetch origin "${BASE_BRANCH}" --depth=100

  # Get list of changed files
  CHANGED_FILES=$(git diff --name-only "origin/${BASE_BRANCH}...HEAD" || true)

  if [[ -z "${CHANGED_FILES}" ]]; then
    echo "No changed files detected" >&2
    return 1
  fi

  echo "Changed files:" >&2
  echo "${CHANGED_FILES}" >&2

  # Check if any packaging files were modified
  for pattern in "${PACKAGING_FILES[@]}"; do
    if echo "${CHANGED_FILES}" | grep -q "^${pattern}"; then
      echo "Packaging files modified (matched: ${pattern})" >&2
      return 0
    fi
  done

  echo "No packaging files modified" >&2
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

# Get versions and variants based on tier
get_test_config() {
  local tier=$1
  local versions_yaml
  local variants_yaml

  case "${tier}" in
    tier1)
      echo "Using Tier 1: Min/max K8s versions, basic container image" >&2
      versions_yaml="[\"${K8S_MIN_VERSION}\", \"${K8S_MAX_VERSION}\"]"
      variants_yaml="${DEFAULT_VARIANT}"
      ;;
    tier2)
      echo "Using Tier 2: Min/max K8s versions, all container images" >&2
      versions_yaml="[\"${K8S_MIN_VERSION}\", \"${K8S_MAX_VERSION}\"]"
      variants_yaml="${ALL_VARIANTS}"
      ;;
    tier3)
      echo "Using Tier 3: All K8s versions, all container images" >&2
      versions_yaml="${ALL_VERSIONS}"
      variants_yaml="${ALL_VARIANTS}"
      ;;
    *)
      echo "ERROR: Unknown tier: ${tier}" >&2
      exit 1
      ;;
  esac

  echo "${versions_yaml}|${variants_yaml}"
}

# Generate the complete pipeline YAML with matrix embedded
generate_pipeline() {
  local versions_yaml=$1
  local variants_yaml=$2

  cat <<EOF
common:
  - google_oidc_observability_plugin: &google_oidc_observability_plugin
      elastic/oblt-google-auth#v1.3.0:
        lifetime: 10800
  - oblt_cli_plugin: &oblt_cli_plugin
      elastic/oblt-cli#v0.4.1:
        version-file: .oblt-cli-version
  - vault_github_token: &vault_github_token
      elastic/vault-github-token#v0.1.0:

steps:
  - group: ":kubernetes: Kubernetes"
    key: integration-tests-kubernetes
    steps:
      - label: ":kubernetes: {{matrix.version}}:amd64:{{matrix.variant}}"
        env:
          K8S_VERSION: "{{matrix.version}}"
          DOCKER_VARIANTS: "{{matrix.variant}}"
          TARGET_ARCH: "amd64"
        command: |
          buildkite-agent artifact download build/distributions/*-linux-amd64.docker.tar.gz . --step 'packaging-containers-amd64'
          .buildkite/scripts/steps/integration_tests_oblt-cli.sh kubernetes false
        artifact_paths:
          - build/*
          - build/diagnostics/**
          - build/*.pod_logs_dump/*
        retry:
          automatic:
            limit: 1
        agents:
          provider: "gcp"
          machineType: "n2-standard-8"
          image: "${IMAGE_UBUNTU_2404_X86_64}"
          diskSizeGb: 80
        plugins:
          - *google_oidc_observability_plugin
          - *oblt_cli_plugin
          - *vault_github_token
        matrix:
          setup:
            version: ${versions_yaml}
            variant: ${variants_yaml}
EOF

}

# Main
main() {
  echo "Determining Kubernetes test tier..." >&2

  K8S_TEST_TIER=$(determine_tier)
  echo "Selected tier: ${K8S_TEST_TIER}" >&2

  # Get test configuration for this tier
  TEST_CONFIG=$(get_test_config "${K8S_TEST_TIER}")
  VERSIONS_YAML=$(echo "${TEST_CONFIG}" | cut -d'|' -f1)
  VARIANTS_YAML=$(echo "${TEST_CONFIG}" | cut -d'|' -f2)

  echo "Versions: ${VERSIONS_YAML}" >&2
  echo "Variants: ${VARIANTS_YAML}" >&2

  # Generate the complete pipeline with embedded matrix
  PIPELINE_FILE=$(mktemp)
  trap 'rm -f ${PIPELINE_FILE}' EXIT

  generate_pipeline "${VERSIONS_YAML}" "${VARIANTS_YAML}" > "${PIPELINE_FILE}"

  echo "Generated pipeline:" >&2
  cat "${PIPELINE_FILE}" >&2

  # Upload the generated pipeline
  echo "Uploading Kubernetes test pipeline..." >&2
  buildkite-agent pipeline upload "${PIPELINE_FILE}"
}

main "$@"

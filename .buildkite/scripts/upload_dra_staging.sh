#!/usr/bin/env bash
# Resolves the full staging stack_version (including VERSION_QUALIFIER) and
# uploads the staging DRA prep + trigger steps as a dynamic pipeline so that
# the qualifier is baked into the stack_version at upload time.
#
# The static pipeline cannot resolve VERSION_QUALIFIER ahead of time because
# it is fetched from GCS at runtime — so this generator runs first, reads the
# qualifier, and emits a concrete pipeline for Buildkite to schedule.
set -euo pipefail

# shellcheck source=.buildkite/scripts/common.sh
source "$(dirname "$0")/common.sh"
# shellcheck source=.buildkite/scripts/version_qualifier.sh
source "$(dirname "$0")/version_qualifier.sh"

# Build the full version string: "8.19.0" + optional "-alpha1" qualifier.
if [[ -n "${VERSION_QUALIFIER:-}" ]]; then
  STACK_VERSION="${BEAT_VERSION}-${VERSION_QUALIFIER}"
else
  STACK_VERSION="${BEAT_VERSION}"
fi

echo "--- :pipeline: Uploading staging DRA steps for ${STACK_VERSION}"

buildkite-agent pipeline upload <<EOF
steps:
  - label: ":package: DRA Prep elastic-agent-core / ${STACK_VERSION} / staging"
    key: "dra-prep-staging"
    command: ".buildkite/scripts/stage_artifacts.sh"
    agents:
      image: "docker.elastic.co/release-eng/wolfi-build-essential-release-eng:latest"
      cpu: "2"
      memory: "4Gi"
      ephemeralStorage: "10Gi"
    env:
      DRA_WORKFLOW: "staging"
    plugins:
      - elastic/oblt-google-auth#v1.3.1:
          lifetime: 10800
          project-id: "elastic-observability-ci"
          project-number: "911195782929"
      - elastic/dra-prep#v0.1.6:
          product_id: "elastic-agent-core"
          stack_version: "${STACK_VERSION}"
          workflow: "staging"

  - label: ":pipeline: DRA processing for elastic-agent-core / ${STACK_VERSION} / staging"
    trigger: "unified-release-dra-processing"
    depends_on: "dra-prep-staging"
    build:
      env:
        DRA_PRODUCT_ID: "elastic-agent-core"
        DRA_STACK_VERSION: "${STACK_VERSION}"
        DRA_WORKFLOW: "staging"
EOF

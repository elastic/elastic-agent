#!/usr/bin/env bash

set -eo pipefail

AUTODISCOVERY_YAML_FILE="${PWD}/build/discovered_tests.yaml"
echo "--- Autodiscovering tests"
[ -d "${PWD}/build" ] || mkdir -p "${PWD}/build"

go test -tags integration github.com/elastic/elastic-agent/testing/integration -v -args -integration.dry-run=true -integration.autodiscover -integration.autodiscoveryoutput="${AUTODISCOVERY_YAML_FILE}"
GROUPS_YAML=$(yq '[.[].groups.[].name]|unique' "${AUTODISCOVERY_YAML_FILE}")
echo "--- Test autodiscovery output: ${AUTODISCOVERY_YAML_FILE}"
echo "--- Detected groups"
echo "${GROUPS_YAML}"
echo "--- Generating dynamic pipeline"
DYNAMIC_PIPELINE="${PWD}/build/dyn.pipeline.yml"
# The 'has("steps")' filter is needed to avoid creating empty arrays in 'label' items
GROUPS_YAML=${GROUPS_YAML} yq '((.steps.[]|select(has("steps"))).steps.[].matrix=env(GROUPS_YAML))' .buildkite/bk.integration.pipeline.yml > "${DYNAMIC_PIPELINE}"
echo "--- Generated dynamic pipeline in ${DYNAMIC_PIPELINE}"
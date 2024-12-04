#!/usr/bin/env bash

set -eo pipefail

echo "--- Autodiscovering tests"
[ -d "${PWD}/build" ] || mkdir -p "${PWD}/build"

IT_YAML_FILE="${PWD}/build/discovered_tests.yaml"
go mod download
echo "--- Downloaded go mods"
go test -tags integration github.com/elastic/elastic-agent/testing/integration -v -args -integration.dry-run=true -integration.autodiscover -integration.autodiscoveryoutput=${IT_YAML_FILE}
GROUPS_YAML=$(yq '[.[].groups.[].name]|unique' ${IT_YAML_FILE})
echo "--- Detected groups"
echo ${GROUPS_YAML}
echo "--- Generating dynamic pipeline"
DYN_PIPELINE="${PWD}/build/dyn.pipeline.yml"
# The 'has("steps")' filter is needed to avoid creating empty arrays in 'label' items
GROUPS_YAML=${GROUPS_YAML} yq '((.steps.[]|has("steps")).steps.[]|has("matrix")).matrix=env(GROUPS_YAML)' .buildkite/bk.integration.pipeline.yml > "${DYN_PIPELINE}"
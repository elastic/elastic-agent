#!/usr/bin/env bash
set -euo pipefail

preinstalled_packages_filename="testing/integration/testdata/preinstalled_packages.json"

# preinstall_fleet_packages installs EPM packages needed for integration tests into Fleet.
function preinstall_fleet_packages() {
  echo "Preinstalling the following EPM packages in Fleet:"
  cat "$preinstalled_packages_filename"

  install_fleet_packages "$preinstalled_packages_filename"
  retcode=$?

  echo "Return code in preinstall_fleet_packages: " $retcode
  return $retcode
}

# install_fleet_packages installs the EPM packages defined in the given file into Fleet. The file
# must define the packages as the request body of the Bulk install packages Fleet API:
# https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-bulk-install-packages
function install_fleet_packages() {
  local install_api_request_file=$1
  if [ -z "$install_api_request_file" ]; then
    echo "Error: Fleet packages installation request file not specified"
    return 1
  fi

  if ! [ -f "$install_api_request_file" ]; then
    echo "Error: Fleet packages installation request file [$install_api_request_file] does not exist"
    return 2
  fi

  if [ -z "$KIBANA_HOST" ]; then
    echo "Error: Kibana hostname not specified via KIBANA_HOST environment variable"
    return 3
  fi

  if [ -z "$KIBANA_USERNAME" ]; then
    echo "Error: Kibana username not specified via KIBANA_USERNAME environment variable"
    return 4
  fi

  if [ -z "$KIBANA_PASSWORD" ]; then
    echo "Error: Kibana password not specified via KIBANA_PASSWORD environment variable"
    return 5
  fi

  resp=$(curl \
    -v \
    -s \
    --fail-with-body \
    -X "POST" \
    -u "${KIBANA_USERNAME}:${KIBANA_PASSWORD}" \
    -d @"${install_api_request_file}" \
    -H 'Content-Type: application/json' \
    -H 'kbn-xsrf: elastic-agent' \
    "${KIBANA_HOST}/api/fleet/epm/packages/_bulk")

  echo "$resp"

  # Parse response body for any errors
  num_errors=$(echo "$resp" | jq '.items[].statusCode | select(.>=400)' | wc -l)
  if [ "$num_errors" -gt 0 ]; then
    return 6
  fi
}

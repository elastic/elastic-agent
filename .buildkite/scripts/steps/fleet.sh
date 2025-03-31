#!/usr/bin/env bash
set -euo pipefail

# preinstall_fleet_packages installs EPM packages needed for integration tests into Fleet.
func preinstall_fleet_packages() {
  install_fleet_packages "testing/integration/testdata/preinstalled_packages.json"
}

# install_fleet_packages installs the EPM packages defined in the given file into Fleet. The file
# must define the packages as the request body of the Bulk install packages Fleet API:
# https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-bulk-install-packages
func install_fleet_packages() {
  local install_api_request_file=$1
  if [ -z "$install_api_request_file" ]; then
    echo "Error: Fleet packages installation request file not specified"
    return 1
  fi

  if ! [[ -f "$install_api_request_file"]]; then
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

  echo "Installing Fleet packages"
  curl -v \
    -X "POST" \
    -u "${KIBANA_USERNAME}:${KIBANA_PASSWORD}" \
    -d @${install_api_request_file} \
    -H 'Content-Type: application/json' \
    -H 'kbn-xsrf: elastic-agent' \
    ${KIBANA_HOST}/api/fleet/epm/packages/_bulk
}

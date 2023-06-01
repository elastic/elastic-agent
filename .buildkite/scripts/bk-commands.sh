#!/usr/bin/env bash
set -exuo pipefail

install_gcloud () {
  if ! command -v gcloud &>/dev/null; then
    echo "Google Cloud SDK is not installed. Installing Google Cloud SDK..."

    # Add the Cloud SDK distribution URI as a package source
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list

    # Import the Google Cloud public key
    curl -S https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

    sudo apt update
    sudo apt-get install google-cloud-sdk -y
    echo "Google Cloud SDK has been installed."
  else
    echo "Google Cloud SDK is already installed."
  fi
}

init_gcloud () {
  install_gcloud
  vault kv get -format=json -field=data kv/ci-shared/observability-ingest/cloud/gcp > ./gcp.json
  export GOOGLE_APPLICATION_CREDENTIALS=$(realpath ./gcp.json)
  export TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE=$(realpath ./gcp.json)  
  gcloud auth activate-service-account --key-file $GOOGLE_APPLICATION_CREDENTIALS 2> /dev/null
}

retry() {
  local retries=$1
  shift

  local count=0
  until "$@"; do
      exit=$?
      wait=$((2 ** count))
      count=$((count + 1))
      if [ $count -lt "$retries" ]; then
          >&2 echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
          sleep $wait
      else
          >&2 echo "Retry $count/$retries exited $exit, no more retries left."
          return $exit
      fi
  done
  return 0
}
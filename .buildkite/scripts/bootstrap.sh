#!/usr/bin/env bash
set -euxo pipefail

# this is required in order to allow the build process to override the default PWD of the BEAT_NAME.
export BEAT_NAME="elastic-agent"

if [[ -z "${WORKSPACE-""}" ]]; then
    WORKSPACE=$(git rev-parse --show-toplevel)
    export WORKSPACE
fi

# Retrieve version value - will match versions like 8.8.0 and also 8.8.0-er1
export BEAT_VERSION=`grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\-[a-zA-Z]+[0-9]+)?' ${WORKSPACE}/version/version.go`
export BRANCH="${BUILDKITE_BRANCH}"

if ! command -v go &>/dev/null; then
  echo "Go is not installed. Installing Go..."  
  retry 5 curl -O https://dl.google.com/go/go$GO_VERSION.linux-amd64.tar.gz
  sudo tar -xf go$GO_VERSION.linux-amd64.tar.gz -C /usr/local
  mkdir -p $HOME/go/bin
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  echo "Go has been installed."
else
  echo "Go is already installed."
fi

# Install mage
make mage

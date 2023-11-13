#!/usr/bin/env bash

# Required environment variables:
# - GH_VERSION - the version of gh to install
set -exuo pipefail

echo "--- Install gh cli"

MSG="environment variable missing."
DEFAULT_HOME="/usr/local"
GH_VERSION=${GH_VERSION:?$MSG}
HOME=${HOME:?$DEFAULT_HOME}
GH_CMD="${HOME}/bin/gh"

if command -v gh
then
    set +e
    echo "Found GH. Checking version.."
    FOUND_GH_VERSION=$(gh --version 2>&1 >/dev/null | awk '{print $3}')
    if [ "$FOUND_GH_VERSION" == "$GH_VERSION" ]
    then
        echo "GH Versions match: $GH_VERSION. No need to install gh. Exiting."
        exit 0
    else 
        echo "GH VErsion mismatch. Desired version: $GH_VERSION, found version: $FOUND_GH_VERSION. Installing new version."    
    fi
    set -e
fi

OS=$(uname -s| tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m| tr '[:upper:]' '[:lower:]')
if [ "${ARCH}" == "aarch64" ] ; then
    ARCH_SUFFIX=arm64
else
    ARCH_SUFFIX=amd64
fi

echo "Downloading gh : ${GH_VERSION}..."
TMP_DIR=$(mktemp -d)
if curl -sL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_${OS}_${ARCH}.tar.gz" | tar xz -C $TMP_DIR ; then
  mkdir -p "${HOME}/bin"
  mv "${TMP_DIR}/gh_${GH_VERSION}_${OS}_${ARCH}/bin/gh" "${GH_CMD}"
  rm -rf ${TMP_DIR}
else
    echo "Something bad with the download, let's delete the corrupted binary"
    if [ -e "${GH_CMD}" ] ; then
        rm "${GH_CMD}"
    fi
    exit 1
fi  



#!/usr/bin/env bash
set -euxo pipefail

# this is required in order to allow the build process to override the default PWD of the BEAT_NAME.
export BEAT_NAME="elastic-agent"

if [[ -z "${WORKSPACE-""}" ]]; then
    WORKSPACE=$(git rev-parse --show-toplevel)
    export WORKSPACE
fi

if [[ -z "${SETUP_MAGE_VERSION-""}" ]]; then
    SETUP_MAGE_VERSION="1.14.0"
fi

if [[ -z "${SETUP_GVM_VERSION-""}" ]]; then
    SETUP_GVM_VERSION="v0.5.0"
fi

if [[ -z "${GO_VERSION-""}" ]]; then
    GO_VERSION=$(cat "${WORKSPACE}/.go-version")
fi

# Retrieve version value
export BEAT_VERSION=$(grep -oe "\d.\d.\d[-\w\d]*" ${WORKSPACE}/version/version.go)
export BRANCH="${BUILDKITE_BRANCH}"

# Wrapper function for executing mage
mage() {
    go version
    if ! [ -x "$(type -p mage | sed 's/mage is //g')" ];
    then
        echo "+++ Installing mage ${SETUP_MAGE_VERSION}"
        make mage
    fi
    pushd "$WORKSPACE"
    command "mage" "$@"
    popd
}

# Wrapper function for executing go
go(){
    # Search for the go in the Path
    if ! [ -x "$(type -p go | sed 's/go is //g')" ];
    then
        local _bin="${WORKSPACE}/bin"
        mkdir -p "${_bin}"
        retry 5 curl -sL -o "${_bin}/gvm" "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-linux-amd64"
        chmod +x "${_bin}/gvm"
        eval "$(command "${_bin}/gvm" "${GO_VERSION}" )"
        export GOPATH=$(command go env GOPATH)
        export PATH="${PATH}:${GOPATH}/bin"
    fi
    pushd "$WORKSPACE"
    command go "$@"
    popd
}

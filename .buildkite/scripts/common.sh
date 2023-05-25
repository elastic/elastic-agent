#!/bin/bash

set -exuo pipefail

if [[ -z "${WORKSPACE-""}" ]]; then
    WORKSPACE=$(git rev-parse --show-toplevel)
fi
PIPELINE="${WORKSPACE}/.buildkite/pipeline.elastic-agent-package.yml"
if [[ -z "${SETUP_MAGE_VERSION-""}" ]]; then
    SETUP_MAGE_VERSION=$(grep -oe "SETUP_MAGE_VERSION\: [\"'].*[\"']" "$PIPELINE" | awk '{print $2}' | sed "s/'//g" )
fi
if [[ -z "${SETUP_GVM_VERSION-""}" ]]; then
    SETUP_GVM_VERSION=$(grep -oe "SETUP_GVM_VERSION\: [\"'].*[\"']" "$PIPELINE" | awk '{print $2}' | sed "s/'//g" )
fi
if [[ -z "${GO_VERSION-""}" ]]; then
    GO_VERSION=$(cat "${WORKSPACE}/.go-version")
fi

# Wrapper function for executing mage
mage() {
    go version
    if ! [ -x "$(type -p mage | sed 's/mage is //g')" ];
    then
        echo "--- installing mage ${SETUP_MAGE_VERSION}"
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
        echo "--- installing golang "${GO_VERSION}""
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

google_cloud_auth() {
    local keyFile=$1

    gcloud auth activate-service-account --key-file ${keyFile} 2> /dev/null

    export GOOGLE_APPLICATIONS_CREDENTIALS=${secretFileLocation}
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

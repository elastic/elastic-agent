#!/usr/bin/env bash
set -euo pipefail

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


AGENT_USER="$(whoami)"
AGENT_HOME="$(eval echo "~${AGENT_USER}")"
ASDF_DIR="${ASDF_DIR:-"$AGENT_HOME/.asdf"}"

echo "~~~ Installing ASDF in ${ASDF_DIR} for user ${AGENT_USER}"
# Installation instructions from https://asdf-vm.com/guide/getting-started.html
ASDF_VERSION="v0.14.1"

retry 5 git clone https://github.com/asdf-vm/asdf.git ${ASDF_DIR} --branch ${ASDF_VERSION} 
echo "source $ASDF_DIR/asdf.sh" >> $AGENT_HOME/.bashrc 
source $ASDF_DIR/asdf.sh
asdf version

asdf plugin update --all
asdf plugin add terraform
asdf plugin add golang
asdf plugin add mage

echo "~~~ Installing golang $(cat .go-version) using ASDF"
export ASDF_GOLANG_VERSION="$(cat .go-version)"
asdf install

export GOROOT="$(asdf where golang)/go/"
export GOPATH=$(go env GOPATH)
export PATH="$GOPATH/bin:$PATH"
go version

echo "~~~ Installing go packages using ASDF"
asdf exec go install gotest.tools/gotestsum@latest
asdf exec go install github.com/alexec/junit2html@latest
asdf reshim golang

umask 0022
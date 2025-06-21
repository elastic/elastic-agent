#!/usr/bin/env bash
set -euo pipefail

AGENT_USER="${AGENT_USER:-"$USER"}"
AGENT_HOME="${AGENT_HOME:-"/Users/$AGENT_USER"}"
ASDF_DIR="${ASDF_DIR:-"/Users/$AGENT_USER/.asdf"}"

echo "~~~ Installing ASDF in ${ASDF_DIR} for user ${AGENT_USER}"
# Installation instructions from https://asdf-vm.com/guide/getting-started.html
ASDF_VERSION="v0.14.1"

# todo retry
git clone https://github.com/asdf-vm/asdf.git ${ASDF_DIR} --branch ${ASDF_VERSION} 
echo 'source $ASDF_DIR/asdf.sh' >> $AGENT_HOME/.bashrc 
source $ASDF_DIR/asdf.sh
asdf version
asdf plugin update --all

echo "~~~ Installing golang $(cat .go-version) using ASDF"
export GOROOT="$(asdf where golang)/go/"
export GOPATH=$(go env GOPATH)
export PATH="$GOPATH/bin:$PATH"
go version
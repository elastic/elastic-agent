#!/usr/bin/env bash
set -euo pipefail

AGENT_USER=buildkite-agent
AGENT_HOME="/opt/buildkite-agent"
ASDF_DIR="/opt/buildkite-agent/.asdf"

###
### ASDF 
###
# Installation instructions from https://asdf-vm.com/guide/getting-started.html
ASDF_VERSION="0.14.0"

function asdf_install() {
  echo "installing asdf $ASDF_VERSION"
  if [ -d "$ASDF_DIR" ]; then
    rm -r "$ASDF_DIR"
  fi
  pushd $AGENT_HOME
  retry -t 3 -- git clone https://github.com/asdf-vm/asdf.git ${ASDF_DIR} --branch v${ASDF_VERSION} 
  echo 'source $ASDF_DIR/asdf.sh' >> $AGENT_HOME/.bashrc
  source $ASDF_DIR/asdf.sh
  asdf plugin update --all
  asdf plugin-add golang https://github.com/asdf-community/asdf-golang.git
  source $AGENT_HOME/.bashrc
}

function asdf_init() {
  source $AGENT_HOME/.bashrc  
  if [[ -f ".tool-versions" ]]; then
    cut -d' ' -f1 .tool-versions|xargs -i asdf plugin add  {}
  fi
  if [[ -f ".go-version" ]]; then
    export ASDF_GOLANG_VERSION=$(cat .go-version)
    install_tool_version_if_absent golang $ASDF_GOLANG_VERSION
    echo "--- loaded .go-version (${ASDF_GOLANG_VERSION})"
    asdf reshim golang
    export GOROOT="$(asdf where golang)/go/"
    export GOPATH=$(go env GOPATH)
    export PATH="$GOPATH/bin:$PATH"
  fi
}

asdf_install
asdf_init



# source /opt/buildkite-agent/hooks/pre-command

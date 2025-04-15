#!/usr/bin/env bash
set -euo pipefail

###
### ASDF 
###
# Installation instructions from https://asdf-vm.com/guide/getting-started.html
AGENT_USER=$(whoami)
AGENT_HOME="~/"
ASDF_DIR="~/.asdf"
ASDF_VERSION="0.14.0"

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
popd

# source /opt/buildkite-agent/hooks/pre-command

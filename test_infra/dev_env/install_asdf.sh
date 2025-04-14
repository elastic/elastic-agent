#!//usr/bin/env bash

set -euo pipefail

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

function install_asdf() {
  echo "installing asdf $ASDF_VERSION"
  sudo -u $AGENT_USER bash <<EOF
set -euo pipefail

if [ -d "$ASDF_DIR" ]; then
  rm -r "$ASDF_DIR"
fi

pushd $AGENT_HOME
retry -t 3 -- git clone https://github.com/asdf-vm/asdf.git ${ASDF_DIR} --branch v${ASDF_VERSION} \\
&& echo 'source $ASDF_DIR/asdf.sh' >> $AGENT_HOME/.bashrc \\
&& source $ASDF_DIR/asdf.sh \\
&& asdf plugin update --all \\
&& asdf plugin-add golang https://github.com/asdf-community/asdf-golang.git
popd 
EOF
}

if command -v asdf >/dev/null 2>&1; then
  INSTALLED_VERSION=$(asdf --version | awk '{print $3}')
  echo "Installed version: ${INSTALLED_VERSION}"
  if [[ "$INSTALLED_VERSION" == "$ASDF_VERSION" ]]; then
      echo "asdf version $ASDF_VERSION is already installed. Skipping installation."      
  else
      echo "asdf is installed, but version is $INSTALLED_VERSION (expected $ASDF_VERSION)."
      install_asdf      
  fi
else
  echo "asdf is not installed"
  install_asdf
fi

sudo su $AGENT_USER
source $AGENT_HOME/.bashrc
source /opt/buildkite-agent/hooks/pre-command

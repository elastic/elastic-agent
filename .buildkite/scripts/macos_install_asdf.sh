#!/usr/bin/env bash
set -euo pipefail

install_asdf() {
  echo "$SHELL"

  AGENT_USER="${AGENT_USER:-"$USER"}"
  AGENT_HOME="${AGENT_HOME:-"/Users/$AGENT_USER"}"
  ASDF_DIR="${ASDF_DIR:-"/Users/$AGENT_USER/.asdf"}"

  echo "~~~ Installing ASDF in ${ASDF_DIR} for user ${AGENT_USER}"
  ASDF_VERSION="v0.14.0"

  pushd "$AGENT_HOME" > /dev/null
  trap 'popd > /dev/null' RETURN

  # todo retry
  git clone https://github.com/asdf-vm/asdf.git "$ASDF_DIR" --branch "$ASDF_VERSION"
  echo 'source $ASDF_DIR/asdf.sh' >> "$AGENT_HOME/.bashrc"
  source "$ASDF_DIR/asdf.sh"
  asdf plugin update --all

  asdf plugin add terraform
  asdf plugin add golang
  asdf plugin add mage
}

install_asdf

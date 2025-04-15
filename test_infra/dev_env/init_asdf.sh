#!/usr/bin/env bash
set -euo pipefail

#
# Should be executed in elastic-agent root dir
#
install_tool_version_if_absent() {
  local tool=$1
  local target_version=$2

  # Check if the desired version is already installed
  if asdf list $tool | grep -q "$target_version"; then
    echo "--- $tool $target_version is already installed."
  else
    echo "--- $tool version $target_version is missing; installing."
    asdf install $tool "$target_version"
  fi
}

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

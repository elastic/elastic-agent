#!/bin/bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/common.sh"

if test -z "${ManifestURL=:""}"; then
  echo "Missing variable ManifestURL, export it before use."
  exit 2
fi

export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p $AGENT_DROP_PATH

# Download the components from the ManifestURL and then package those downloaded into the $AGENT_DROP_PATH
mage clean downloadManifest package

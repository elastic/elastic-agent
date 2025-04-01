#!/usr/bin/env bash
set -eo pipefail

ASDF_DIR=~/.asdf
ASDF_VERSION="v0.14.0"

# Installation instructions from https://asdf-vm.com/guide/getting-started.html
if ! command -v asdf ; then
    echo "--- Install asdf"
    git clone https://github.com/asdf-vm/asdf.git ${ASDF_DIR} --branch ${ASDF_VERSION}
    echo "source $ASDF_DIR/asdf.sh" >> ~/.bashrc
    source $ASDF_DIR/asdf.sh
    asdf plugin update --all
fi

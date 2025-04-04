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
    echo "--- Install asdf plugins"
    # See https://github.com/asdf-vm/asdf/issues/276#issuecomment-1135177059
    cat .tool-versions | cut -d' ' -f1 | grep "^[^\#]" | xargs -i asdf plugin add  {}
fi

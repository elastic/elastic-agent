#!/usr/bin/env bash
set -euo pipefail

echo "--- Install awscli"

DEFAULT_HOME="/usr/local"
HOME=${HOME:?$DEFAULT_HOME}
HOME_BIN="${HOME}/bin"
AWSCLI_INSTALL_DIR="${HOME}/awscli"

if command -v aws
then
    set +e
    echo "Found awscli."
fi

echo "Installing awscli"

mkdir -p "${HOME_BIN}"
mkdir -p "${AWSCLI_INSTALL_DIR}"

ARCH=$(uname -m| tr '[:upper:]' '[:lower:]')

curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
sudo ./aws/install


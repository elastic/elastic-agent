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

OS=$(uname -s| tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m| tr '[:upper:]' '[:lower:]')

curl "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install --bin-dir "${HOME_BIN}" --install-dir "${AWSCLI_INSTALL_DIR}"


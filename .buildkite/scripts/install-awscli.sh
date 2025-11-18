#!/usr/bin/env bash
set -euo pipefail

echo "--- Install awscli"

DEFAULT_HOME="/usr/local"
HOME=${HOME:?$DEFAULT_HOME}

if command -v aws
then
    set +e
    echo "Found awscli."
    exit 0
fi

echo "Installing awscli"

ARCH=$(uname -m| tr '[:upper:]' '[:lower:]')

echo "ARCH: $ARCH OSTYPE: $OSTYPE SHELL: $SHELL PATH: $PATH"

if [[ "$OSTYPE" == "linux-gnu" ]]; then
  curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip
  sudo ./aws/install
  if ! command -v aws; then
      export PATH="/usr/local/bin:${PATH}"
  fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
  curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
  sudo installer -pkg AWSCLIV2.pkg -target / -verbose -dumplog
fi
hash -r
echo "AWS CLI installed. Version:"
aws --version

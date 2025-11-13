#!/usr/bin/env bash
set -euo pipefail

echo "--- Install awscli"

DEFAULT_HOME="/usr/local"
HOME=${HOME:?$DEFAULT_HOME}

if command -v aws
then
    set +e
    echo "Found awscli."
fi

echo "Installing awscli"

ARCH=$(uname -m| tr '[:upper:]' '[:lower:]')

if [[ "$OSTYPE" == "linux-gnu" ]]; then
  curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip
  sudo ./aws/install
elif [[ "$OSTYPE" == "darwin" ]]; then
  curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
  sudo installer -pkg AWSCLIV2.pkg -target / -verbose -dumplog
  hash -r
  echo "Shell: $SHELL"
  echo "Updating PATH to include AWS CLI..."
  export PATH="/usr/local/aws-cli/v2/current/bin:$PATH"
  ls -al /usr/local/aws-cli/v2/current/bin
fi
echo "AWS CLI installed. Version:"
aws --version

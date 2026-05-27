#!/usr/bin/env bash
set -euo pipefail

echo "--- Install awscli"

DEFAULT_HOME="/usr/local"
HOME=${HOME:?$DEFAULT_HOME}

if command -v aws
then
    set +e
    echo "Found awscli."
    aws --version
    exit 0
fi

# awscli is pre-installed on Linux and Windows VM images; only install on macOS.
if [[ "$OSTYPE" != "darwin"* ]]; then
  echo "awscli not found and OS is not macOS — skipping installation"
  exit 1
fi

echo "Installing awscli"

curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target / -verbose -dumplog
hash -r
echo "AWS CLI installed. Version:"
aws --version

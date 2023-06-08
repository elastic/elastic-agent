#!/usr/bin/env bash
set -exuo pipefail

# Install Go TODO: mode to makefile
if ! command -v go &>/dev/null; then  
  echo "Go is not installed. Installing Go..."
  export GO_VERSION=`cat .go-version`
  curl -O https://dl.google.com/go/go$GO_VERSION.linux-amd64.tar.gz
  sudo tar -xf go$GO_VERSION.linux-amd64.tar.gz -C /usr/local
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  source ~/.bashrc
  mkdir $HOME/go
  mkdir $HOME/go/bin
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin  
  echo "Go has been installed."
else
  echo "Go is already installed."
fi

# Install mage
make mage

# PACKAGE
DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64 PACKAGES=tar.gz mage package

# Run integration tests
AGENT_VERSION=8.9.0-SNAPSHOT mage integration:test

# HTML report
go install github.com/alexec/junit2html@latest
junit2html < build/TEST-go-integration.xml > build/TEST-report.html

# A HORRIBLE hack to detect test failures
if grep "<failure" build/TEST-go-integration.xml; then  
  echo "Tests failed."
  exit 1
fi

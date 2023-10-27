#!/usr/bin/env bash
set -euo pipefail

cd build

git clone git@github.com:elastic/beats.git

cd beats

SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package
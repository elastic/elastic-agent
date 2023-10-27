#!/usr/bin/env bash
set -euo pipefail

export WORKSPACE=build/beats/x-pack/metricbeat

source .buildkite/scripts/common.sh

mkdir -p build
cd build

git clone git@github.com:elastic/beats.git
cd beats

SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package
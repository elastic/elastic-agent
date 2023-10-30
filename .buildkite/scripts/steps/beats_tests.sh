#!/usr/bin/env bash
set -euo pipefail
set -x

source .buildkite/scripts/common.sh

mage -l

mkdir -p build
cd build

git clone git@github.com:elastic/beats.git

#cd beats/x-pack/metricbeat
export WORKSPACE=build/beats/x-pack/metricbeat
ls
SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package
#!/bin/bash
set -euo pipefail

source .buildkite/scripts/common.sh

export PATH=$HOME/bin:${PATH}
source .buildkite/scripts/install-kubectl.sh
source .buildkite/scripts/install-kind.sh

# Increase max inotify instances and watches to avoid 'too many open files' errors
# when spawning more than one k8s cluster
sudo sysctl fs.inotify.max_user_instances=1280
sudo sysctl fs.inotify.max_user_watches=655360

# Run k8s integration tests
set +e

arch_type="$(uname -m)"
if [ "${arch_type}" == "x86_64" ]; then
  export PLATFORMS="linux/amd64"
elif [[ "${arch_type}" == "aarch64" || "${arch_type}" == "arm64" ]]; then
  export PLATFORMS="linux/arm64"
else
  echo "Unsupported OS"
  exit 10
fi

AGENT_VERSION="8.16.0-SNAPSHOT" DEV=true SNAPSHOT=true EXTERNAL=true PACKAGES=docker mage -v package
TEST_INTEG_CLEAN_ON_EXIT=true INSTANCE_PROVISIONER=kind STACK_PROVISIONER=stateful SNAPSHOT=true mage integration:kubernetes
TESTS_EXIT_STATUS=$?
set -e

# HTML report
outputXML="build/TEST-go-integration.xml"

if [ -f "$outputXML" ]; then
  go install github.com/alexec/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS

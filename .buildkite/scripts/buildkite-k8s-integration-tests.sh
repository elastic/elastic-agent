#!/usr/bin/env bash
set -euo pipefail

: "${K8S_PROVISIONER:?Error: Specify the Kubernetes provisioner via K8S_PROVISIONER env variable}"
: "${K8S_VERSION:?Error: Specify the cluster version via K8S_VERSION env variable}"
: "${TARGET_ARCH:?Error: Specify target architecture via TARGET_ARCH env variable}"
: "${DOCKER_VARIANTS:?Error: Specify the Docker variants via DOCKER_VARIANTS env variable}"
: "${DOCKER_IMAGE_ARCHIVES_DIR:=build/distributions}"

if [[ -z "${AGENT_VERSION:-}" ]]; then
  if [[ -f "${WORKSPACE}/.package-version" ]]; then
    AGENT_VERSION="$(jq -r '.version' .package-version)"
    echo "~~~ Agent version: ${AGENT_VERSION} (from .package-version)"
  else
    AGENT_VERSION="$(grep "const defaultBeatVersion =" version/version.go | cut -d\" -f2)"
    AGENT_VERSION="${AGENT_VERSION}-SNAPSHOT"
    echo "~~~ Agent version: ${AGENT_VERSION} (from version/version.go)"
  fi
  export AGENT_VERSION
else
  echo "~~~ Agent version: ${AGENT_VERSION} (specified by env var)"
fi

# Buildkite defines K8S_VERSION with a v prefix (for example "v1.34.0") but mage
# expects it without.
K8S_VERSION="${K8S_VERSION#v}"
echo "~~~ Kubernetes version: ${K8S_VERSION}"

GOTEST_FLAGS=""
if [[ "${BUILDKITE_PULL_REQUEST:="false"}" != "false" ]]; then
  GOTEST_FLAGS="-test.short"
fi

IFS=',' read -r -a docker_variants <<< "${DOCKER_VARIANTS}"

echo "~~~ Loading Docker images"
for variant in "${docker_variants[@]}"; do
  # construct image archive path
  image_archive="elastic-agent-${variant}-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  if [[ "${variant}" == "basic" ]]; then
    image_archive="elastic-agent-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  elif [[ "${variant}" == "elastic-otel-collector" ]]; then
    image_archive="elastic-otel-collector-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  elif [[ "${variant}" == "elastic-otel-collector-wolfi" ]]; then
    image_archive="elastic-otel-collector-wolfi-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  fi
  image_archive_path="${DOCKER_IMAGE_ARCHIVES_DIR}/${image_archive}"

  # Check that manifest.json is present in image archive
  # NOTE: Do not use --wildcards option because it is not supported on MacOS
  # NOTE: Do not pipe tar output directly to grep as the former might take some
  #       time before printing all contents, especially for large archives, and
  #       the latter might exit pre-maturely
  if ! tar_output=$(tar -tf "${image_archive_path}"); then
      echo "Error: Failed to read tar archive ${image_archive_path}" >&2
      exit 1
  fi
  if ! echo "$tar_output" | grep -q "manifest.json"; then
      echo "Error: manifest.json not found in ${image_archive_path}" >&2
      exit 1
  fi

  # load image
  echo "Loading Docker image from ${image_archive_path}"
  BUILDKIT_PROGRESS=plain docker load -i "${image_archive_path}"
done

TESTS_EXIT_STATUS=0
for variant in "${docker_variants[@]}"; do
  echo "~~~ Kubernetes integration tests for variant: ${variant}"

  # We are setting TEST_INTEG_CLEAN_ON_EXIT=false because the .buildkite/hooks/pre-exit script
  # will automatically clean up the kubernetes clusters on CI completion.
  set +e
  INSTANCE_PROVISIONER="${K8S_PROVISIONER}" \
    STACK_PROVISIONER=external \
    TEST_PLATFORMS="kubernetes/${TARGET_ARCH}/${K8S_VERSION}/${variant}" \
    GOTEST_FLAGS="${GOTEST_FLAGS}" \
    TEST_INTEG_CLEAN_ON_EXIT=false \
    mage -v integration:testKubernetes
  exit_status=$?
  set -e

  if [[ $exit_status -ne 0 ]]; then
    echo "^^^ +++"
  fi

  if [[ $TESTS_EXIT_STATUS -eq 0 && $exit_status -ne 0 ]]; then
    TESTS_EXIT_STATUS=$exit_status
  fi
done

exit $TESTS_EXIT_STATUS

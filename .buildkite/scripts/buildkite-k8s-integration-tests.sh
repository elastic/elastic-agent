#!/usr/bin/env bash
set -euo pipefail

: "${K8S_VERSION:?Error: Specify Kubernetes version via K8S_VERSION env variable}"
: "${TARGET_ARCH:?Error: Specify target architecture via ARCH env variable}"
: "${DOCKER_IMAGE_ARCHIVES_DIR:=build/distributions}"

DOCKER_VARIANTS="${DOCKER_VARIANTS:-basic,wolfi,complete,complete-wolfi,service,cloud}"
CLUSTER_NAME="${K8S_VERSION}-kubernetes"

if [[ -z "${AGENT_VERSION:-}" ]]; then
  # If not specified, use the version in version/version.go
  AGENT_VERSION="$(grep "const defaultBeatVersion =" version/version.go | cut -d\" -f2)"
  AGENT_VERSION="${AGENT_VERSION}-SNAPSHOT"
fi

echo "~~~ Create kind cluster '${CLUSTER_NAME}'"
kind create cluster --image  "kindest/node:${K8S_VERSION}" --name "${CLUSTER_NAME}" --wait 60s --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    scheduler:
      extraArgs:
        bind-address: "0.0.0.0"
        secure-port: "10259"
    controllerManager:
      extraArgs:
        bind-address: "0.0.0.0"
        secure-port: "10257"
EOF

IFS=',' read -r -a docker_variants <<< "${DOCKER_VARIANTS}"

echo "~~~ Building k8s inner tests binary"
GOOS=linux GOARCH="${TARGET_ARCH}" CGO_ENABLED=0 go test -tags 'kubernetes_inner' -c -o ./testsBinary ./testing/kubernetes_inner/...
chmod +x ./testsBinary

export TEST_DEFINE_PREFIX="${CLUSTER_NAME}"

go install gotest.tools/gotestsum
gotestsum --version

TESTS_EXIT_STATUS=0
for variant in "${docker_variants[@]}"; do
  echo "~~~ k8s Integration tests for variant: ${variant}"

  # construct image archive path
  image_archive="elastic-agent-${variant}-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  if [[ "${variant}" == "basic" ]]; then
    image_archive="elastic-agent-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  elif [[ "${variant}" == "elastic-otel-collector" ]]; then
    image_archive="elastic-otel-collector-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  elif [[ "${variant}" == "elastic-otel-collector-wolfi" ]]; then
    image_archive="elastic-otel-collector-wolfi-${AGENT_VERSION}-linux-${TARGET_ARCH}.docker.tar.gz"
  fi
  image_archive_path="${DOCKER_IMAGE_ARCHIVES_DIR}/$image_archive"

  # load image
  echo "Loading Docker image from ${image_archive_path}"
  BUILDKIT_PROGRESS=plain docker load -i "${image_archive_path}"

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

  # read image name from manifest
  image=$(tar -Oxf "${image_archive_path}" manifest.json | jq -r '.[0].RepoTags[0]')

  # embed k8s inner tests binary and build again the same image
  echo "Embedding k8s inner tests binary into ${image}"
  BUILDKIT_PROGRESS=plain docker build --tag "${image}" . -f - <<EOF
FROM "${image}"
COPY testsBinary /usr/share/elastic-agent/k8s-inner-tests
EOF

  # load image to kind cluster
  echo "Loading Docker image ${image} to kind cluster ${CLUSTER_NAME}"
  kind load docker-image --name "${CLUSTER_NAME}" "$image"

  # Run integration tests
  echo "Running k8s integration tests for ${variant}"
  group_name="kubernetes"
  fully_qualified_group_name="${CLUSTER_NAME}_${TARGET_ARCH}_${variant}"
  outputXML="build/${fully_qualified_group_name}.integration.xml"
  outputJSON="build/${fully_qualified_group_name}.integration.out.json"
  pod_logs_base="${PWD}/build/${fully_qualified_group_name}.pod_logs_dump"

  set +e
  K8S_TESTS_POD_LOGS_BASE="${pod_logs_base}" AGENT_IMAGE="${image}" DOCKER_VARIANT="${variant}" gotestsum --hide-summary=skipped --format testname --no-color -f standard-quiet --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- -tags kubernetes,integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${group_name}" -integration.sudo="false"
  exit_status=$?
  set -e

  if [[ $TESTS_EXIT_STATUS -eq 0 && $exit_status -ne 0 ]]; then
    TESTS_EXIT_STATUS=$exit_status
  fi
done

exit $TESTS_EXIT_STATUS

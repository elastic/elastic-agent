#!/bin/bash

set -euo pipefail

if [[ -z "${WORKSPACE-""}" ]]; then
    WORKSPACE=$(git rev-parse --show-toplevel)
    export WORKSPACE
fi
if [[ -z "${SETUP_GVM_VERSION-""}" ]]; then
    SETUP_GVM_VERSION="v0.6.0" # https://github.com/andrewkroh/gvm/issues/44#issuecomment-1013231151
fi

if [[ -z "${BEAT_VERSION-""}" ]]; then
  BEAT_VERSION=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\-[a-zA-Z]+[0-9]+)?' "${WORKSPACE}/version/version.go")
  export BEAT_VERSION
fi

# Disable the containerd snapshotter, as it affects the output of docker save.
# See https://github.com/elastic/elastic-agent/issues/11604
docker_disable_containerd_snapshotter() {
  if ! systemctl is-enabled docker; then
    return 0
  fi
  cat << EOF | sudo tee /etc/docker/daemon.json >/dev/null
{
  "features": {
    "containerd-snapshotter": false
  }
}
EOF
  sudo systemctl restart docker
}

docker_disable_containerd_snapshotter

# Disable background package managers to prevent RPM lock contention
# during tests. The dnf-makecache timer periodically refreshes package
# metadata and holds the RPM database lock while doing so, which causes
# "Resource temporarily unavailable" errors when tests run rpm commands.
disable_background_package_managers() {
  if ! command -v dnf >/dev/null 2>&1; then
    return 0
  fi
  echo "Disabling background package managers to prevent RPM lock contention"
  # google-osconfig-agent performs GCP patch management and is a known RPM lock holder
  for unit in dnf-automatic.timer dnf-makecache.timer dnf-makecache.service packagekit.service google-osconfig-agent.service; do
    sudo systemctl disable --now "$unit" 2>/dev/null || true
  done
}

disable_background_package_managers

# On RPM-based systems, log the RPM lock state every 30 seconds in the background.
# This captures which process holds /var/lib/rpm/.rpm.lock so that intermittent
# lock contention failures have context in CI logs even when the failure is flaky.
start_rpm_lock_diagnostics() {
  if ! command -v dnf >/dev/null 2>&1; then
    return 0
  fi
  (
    while true; do
      echo "--- RPM lock diagnostics: $(date -u +%Y-%m-%dT%H:%M:%SZ) ---"
      echo "fuser /var/lib/rpm/.rpm.lock:"
      lock_pids=$(sudo fuser /var/lib/rpm/.rpm.lock 2>/dev/null) || true
      if [[ -n "${lock_pids}" ]]; then
        sudo fuser -v /var/lib/rpm/.rpm.lock 2>&1
        echo "process tree for lock holders:"
        ps -p "$(echo "${lock_pids}" | tr -s ' ' ',' | sed 's/^,//;s/,$//')" -o pid,ppid,cmd 2>&1 || true
      else
        echo "(lock not held)"
      fi
      echo "Running systemd services:"
      systemctl list-units --state=running --type=service --no-pager 2>&1 || true
      sleep 30
    done
  ) &
}

start_rpm_lock_diagnostics

getOSOptions() {
  case $(uname | tr '[:upper:]' '[:lower:]') in
    linux*)
      export AGENT_OS_NAME=linux
      ;;
    darwin*)
      export AGENT_OS_NAME=darwin
      ;;
    msys*)
      export AGENT_OS_NAME=windows
      ;;
    *)
      export AGENT_OS_NAME=notset
      ;;
  esac
  case $(uname -m | tr '[:upper:]' '[:lower:]') in
    aarch64*)
      export AGENT_OS_ARCH=arm64
      ;;
    arm64*)
      export AGENT_OS_ARCH=arm64
      ;;
    amd64*)
      export AGENT_OS_ARCH=amd64
      ;;
    x86_64*)
      export AGENT_OS_ARCH=amd64
      ;;
    *)
      export AGENT_OS_ARCH=notset
      ;;
  esac
}

# Wrapper function for executing mage
mage() {
    go version
    if ! [ -x "$(type -P mage | sed 's/mage is //g')" ];
    then
        make mage
    fi
    pushd "$WORKSPACE"
    command "mage" "$@"
    ACTUAL_EXIT_CODE=$?
    popd
    return $ACTUAL_EXIT_CODE
}

# Wrapper function for executing go
go(){
    # Search for the go in the Path
    if ! [ -x "$(type -P go | sed 's/go is //g')" ];
    then
        getOSOptions
        echo "installing golang "${GO_VERSION}" for "${AGENT_OS_NAME}/${AGENT_OS_ARCH}" "
        local _bin="${WORKSPACE}/bin"
        mkdir -p "${_bin}"
        retry 5 curl -sL -o "${_bin}/gvm" "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-${AGENT_OS_NAME}-${AGENT_OS_ARCH}"
        chmod +x "${_bin}/gvm"
        eval "$(command "${_bin}/gvm" "${GO_VERSION}" )"
        export GOPATH=$(command go env GOPATH)
        export PATH="${PATH}:${GOPATH}/bin"
    fi
    pushd "$WORKSPACE"
    command go "$@"
    ACTUAL_EXIT_CODE=$?
    popd
    return $ACTUAL_EXIT_CODE
}

retry() {
    local retries=$1
    shift

    local count=0
    until "$@"; do
        exit=$?
        wait=$((2 ** count))
        count=$((count + 1))
        if [ $count -lt "$retries" ]; then
            >&2 echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
            sleep $wait
        else
            >&2 echo "Retry $count/$retries exited $exit, no more retries left."
            return $exit
        fi
    done
    return 0
}

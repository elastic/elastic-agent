#!/bin/bash

set -euo pipefail

if [[ -z "${WORKSPACE-""}" ]]; then
    WORKSPACE=$(git rev-parse --show-toplevel)
    export WORKSPACE
fi

BEAT_VERSION=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\-[a-zA-Z]+[0-9]+)?' "${WORKSPACE}/version/version.go")
export BEAT_VERSION

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

google_cloud_auth() {
    local keyFile=$1

    gcloud auth activate-service-account --key-file ${keyFile} 2> /dev/null

    export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

# Prints stack version for current or target release branch without '-SNAPSHOT' suffix 
# example: 
# BUILDKITE_PULL_REQUEST_BASE_BRANCH=8.x .buildkite/scripts/test.sh
# 8.19.0-64846b77
getStableEssSnapshotForBranch() {
  set -eo pipefail

  # If we're on a pull request, use the base branch. Otherwise, use the current branch.
  # This is Buildkite specific
  baseStackBranch="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-${BUILDKITE_BRANCH}}"

  # If no base branch is found, fallback to .package-version content.
  if [ -z "$baseStackBranch" ]; then
    cat .package-version
    return
  fi

  # Fetch the branch channel URL for the base branch if it exists, and the content contains .build.
  branchChannelURL="https://storage.googleapis.com/artifacts-api/channels/${baseStackBranch}.json"
  if ! curl --silent --fail "$branchChannelURL" | jq -r .build; then
    cat .package-version
  fi
}

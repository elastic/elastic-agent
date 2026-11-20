#!/usr/bin/env bash
# Sourced by the container packaging steps in .buildkite/integration.pipeline.yml
# before integration-package.sh. It must be sourced (not executed) so that the
# DOCKER_VARIANTS export reaches the packaging command.
#
# Pull request builds only consume a few of the Docker variants:
#   - wolfi, complete, elastic-otel-collector: Kubernetes tier 1
#   - complete: the heartbeat-complete group
#   - cloud: pushed to docker.elastic.co/beats-ci for the ECH test
# Building all of them (11 on amd64) roughly doubles the time of the step that
# gates every Kubernetes test job, so on PRs we build only that subset.
#
# The subset is only used when the PR cannot change how the images are built
# or which variants the pipeline needs. Any change under the paths matched by
# BUILD_AFFECTING_PATHS builds every variant, exactly like a branch build. The
# list is a superset of the `if_changed` paths that enable the Kubernetes
# tier 2 jobs (.buildkite/**, magefile.go, deploy/**, dev-tools/**, go.mod,
# go.sum), which are the only PR consumers of the other variants.
#
# Branch builds and steps that set DOCKER_VARIANTS explicitly are not affected.

PR_DOCKER_VARIANTS="wolfi,complete,elastic-otel-collector,cloud"

# Regular expression matched against each changed path.
BUILD_AFFECTING_PATHS='^(\.buildkite/|dev-tools/|deploy/|specs/|_meta/|version/|magefile\.go$|go\.mod$|go\.sum$|\.package-version$|\.go-version$|NOTICE(-fips)?\.txt$|LICENSE\.txt$)'

docker_variants_for_pr() {
  if [[ "${BUILDKITE_PULL_REQUEST:-false}" == "false" ]]; then
    echo "~~~ Docker variants: not a pull request build, building all variants"
    return 0
  fi
  if [[ -n "${DOCKER_VARIANTS:-}" ]]; then
    echo "~~~ Docker variants: DOCKER_VARIANTS=${DOCKER_VARIANTS} set explicitly, leaving it alone"
    return 0
  fi

  echo "~~~ Docker variants: selecting the variants to build for this pull request"

  # The post-checkout hook merges the PR onto a base commit pinned in build
  # meta-data (see .buildkite/hooks/post-checkout), so every job of the build
  # compares against the same base. Fall back to building everything whenever
  # the base cannot be determined.
  local target_branch="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-}"
  if [[ -z "${target_branch}" ]]; then
    echo "Target branch unknown, building all variants"
    return 0
  fi
  local base_sha
  base_sha="$(buildkite-agent meta-data get "base_sha_${target_branch//\//_}" 2>/dev/null || true)"
  if [[ -z "${base_sha}" ]]; then
    echo "Base commit not found in build meta-data, building all variants"
    return 0
  fi
  if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
    git fetch --quiet origin "${base_sha}" 2>/dev/null || true
  fi
  if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
    echo "Base commit ${base_sha} is not available locally, building all variants"
    return 0
  fi

  local changed
  if ! changed="$(git diff --name-only "${base_sha}...HEAD")"; then
    echo "Failed to diff against ${base_sha}, building all variants"
    return 0
  fi

  local build_affecting
  build_affecting="$(grep -E "${BUILD_AFFECTING_PATHS}" <<<"${changed}" || true)"
  if [[ -n "${build_affecting}" ]]; then
    echo "The pull request changes files that affect the Docker images or the pipeline, building all variants:"
    echo "${build_affecting}"
    return 0
  fi

  export DOCKER_VARIANTS="${PR_DOCKER_VARIANTS}"
  echo "No build-affecting changes vs ${base_sha}, building only DOCKER_VARIANTS=${DOCKER_VARIANTS}"
}

docker_variants_for_pr

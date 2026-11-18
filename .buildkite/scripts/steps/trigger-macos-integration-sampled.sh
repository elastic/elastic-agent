#!/usr/bin/env bash
#
# Upload an async trigger step for the elastic-agent-macos-integration pipeline for a sample of the commits.
# The Orka pool is small and a full run takes ~2h40m: PRs must never wait for it, and only a few commits run it
# while we gather metrics.
#
# The decision is deterministic (hash of the commit), so a retry of a build gives the same answer.
# A PR labelled "macos-it" always runs it.
#
# Environment variables:
#  - BUILDKITE_COMMIT, BUILDKITE_BRANCH (required)
#  - MACOS_ORKA_SAMPLE_PERCENT: percentage of commits to run, 0-100 (default 5)
#  - GITHUB_PR_LABELS: comma separated labels of the PR (optional)

set -euo pipefail

: "${BUILDKITE_COMMIT:?}"
: "${BUILDKITE_BRANCH:?}"
PERCENT="${MACOS_ORKA_SAMPLE_PERCENT:-5}"
LABELS="${GITHUB_PR_LABELS:-}"

if ! [[ "${PERCENT}" =~ ^[0-9]+$ ]] || ((PERCENT > 100)); then
  echo "Invalid MACOS_ORKA_SAMPLE_PERCENT: ${PERCENT}" >&2
  exit 1
fi

bucket=$(($(printf '%s' "${BUILDKITE_COMMIT}" | cksum | cut -d' ' -f1) % 100))

if [[ ",${LABELS}," == *",macos-it,"* ]]; then
  echo "Label macos-it set: triggering the macOS integration tests"
elif ((bucket < PERCENT)); then
  echo "Commit ${BUILDKITE_COMMIT} is in the sample (bucket ${bucket} < ${PERCENT}%): triggering the macOS integration tests"
else
  echo "Commit ${BUILDKITE_COMMIT} is not in the sample (bucket ${bucket} >= ${PERCENT}%): nothing to trigger"
  exit 0
fi

cat <<YAML | buildkite-agent pipeline upload
steps:
  - label: ":apple: macOS integration tests (Orka, sampled)"
    trigger: "elastic-agent-macos-integration"
    async: true
    build:
      commit: "${BUILDKITE_COMMIT}"
      branch: "${BUILDKITE_BRANCH}"
      message: "PR #${BUILDKITE_PULL_REQUEST:-} (sampled macOS run)"
YAML

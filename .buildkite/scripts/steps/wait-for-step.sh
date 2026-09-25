#!/usr/bin/env bash
# Waits for another step of the current build to finish, so that a job can do
# its own setup (VM boot, tool installation, building test binaries) in
# parallel with the step it needs artifacts from, instead of using depends_on.
#
# Usage: wait-for-step.sh <step-key> [timeout-seconds]
#
# Exits 0 when the step passed, 1 when it failed or the timeout elapsed.
set -euo pipefail

STEP_KEY=${1:?"Usage: wait-for-step.sh <step-key> [timeout-seconds]"}
TIMEOUT_SECONDS=${2:-3600}
POLL_INTERVAL_SECONDS=${WAIT_FOR_STEP_POLL_INTERVAL:-20}

echo "~~~ Waiting for step ${STEP_KEY} to finish"
start=$(date +%s)
while true; do
  # The attribute is only set once the step has finished; treat any error or
  # unknown value as "still running".
  outcome=$(buildkite-agent step get outcome --step "${STEP_KEY}" 2>/dev/null || true)
  case "${outcome}" in
    passed)
      echo "Step ${STEP_KEY} passed after $(( $(date +%s) - start ))s"
      exit 0
      ;;
    hard_failed|soft_failed|errored)
      echo "Step ${STEP_KEY} finished with outcome '${outcome}'" >&2
      exit 1
      ;;
  esac
  if (( $(date +%s) - start >= TIMEOUT_SECONDS )); then
    echo "Timed out after ${TIMEOUT_SECONDS}s waiting for step ${STEP_KEY} (last outcome: '${outcome}')" >&2
    exit 1
  fi
  sleep "${POLL_INTERVAL_SECONDS}"
done

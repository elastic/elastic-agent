#!/usr/bin/env bash
# Generate the plugin-check pipeline for a PR: verify changed plugin pins, then emit
# synthetic probes and dry-run triggers. Prints a Buildkite pipeline on stdout (nothing
# if no pin changed); all diagnostics go to stderr.
#
#   generate.sh [base-ref]   default: origin/$BUILDKITE_PULL_REQUEST_BASE_BRANCH (fetched)
# Exit: 0 ok / 1 tag verification failed / 2 base ref unavailable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

base="${1:-}"
if [[ -z "$base" ]]; then
  branch="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:?BUILDKITE_PULL_REQUEST_BASE_BRANCH or base-ref required}"
  git fetch --no-tags origin "+refs/heads/${branch}:refs/remotes/origin/${branch}" >&2
  base="origin/${branch}"
fi

pins="$("${HERE}/pins.sh" changed "$base")" # exit 2 propagates via set -e
if [[ -z "$pins" ]]; then
  echo "plugin-check: no plugin pin changed vs ${base}" >&2
  exit 0
fi

echo "--- changed plugin pins" >&2
cut -f1,2 <<<"$pins" | sort -u >&2

"${HERE}/verify-tags.sh" <<<"$pins" >&2 || {
  echo "plugin-check: tag verification failed (drafts and missing tags are not allowed)" >&2
  exit 1
}

{
  "${HERE}/gen-probes.sh" <<<"$pins"
  "${HERE}/gen-dryrun.sh" <<<"$pins"
} | awk '/^steps:$/ { if (seen++) next } { print }'

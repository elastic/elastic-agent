#!/usr/bin/env bash
# Downloads built elastic-agent-package artifacts from Buildkite artifact store
# and stages them into artifacts/ for the dra-prep plugin.
set -euo pipefail

WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"

echo "--- :compression: Downloading ${WORKFLOW} artifacts"
mkdir -p build/distributions/

buildkite-agent artifact download "build/distributions/**/*" . || true

if ! ls build/distributions/* 1>/dev/null 2>&1; then
  echo "ERROR: no artifacts found in build/distributions/" >&2
  exit 1
fi

chmod -R a+r build/distributions/

echo "--- :package: Staging ${WORKFLOW} artifacts"
mkdir -p artifacts/

# Copy all build artifacts into artifacts/ for the dra-prep plugin
cp -r build/distributions/. artifacts/

echo "Staged artifacts:"
find artifacts/ -type f | sort

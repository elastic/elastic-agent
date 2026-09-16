#!/usr/bin/env bash
set -euo pipefail

WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"

echo "--- :compression: Downloading ${WORKFLOW} artifacts"

mkdir -p build/distributions/

buildkite-agent artifact download "build/distributions/**/*" .

if ls build/distributions/* 1>/dev/null 2>&1; then
  chmod -R a+r build/distributions/
fi

echo "--- :package: Staging ${WORKFLOW} artifacts"
mkdir -p artifacts

# Copy all binaries (tar.gz, zip, deb, rpm)
find build/distributions -maxdepth 1 \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.deb" -o -name "*.rpm" \) \
  -exec cp {} artifacts/ \; 2>/dev/null || true

# Copy dependency report CSV — snapshot ones have "SNAPSHOT" in the name, staging ones don't
if [[ "${WORKFLOW}" == "snapshot" ]]; then
  find build/distributions/reports -name "*SNAPSHOT*.csv" -exec cp {} artifacts/ \; 2>/dev/null || true
else
  find build/distributions/reports -name "*.csv" ! -name "*SNAPSHOT*" -exec cp {} artifacts/ \; 2>/dev/null || true
fi

if ! ls artifacts/* 1>/dev/null 2>&1; then
  echo "ERROR: no ${WORKFLOW} artifacts found." >&2
  exit 1
fi

echo "Staged artifacts:"
ls -1 artifacts/

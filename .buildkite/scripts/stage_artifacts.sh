#!/usr/bin/env bash
# Prepares the artifacts/ directory for the elastic/dra-prep-buildkite-plugin.
#
# Downloads build output from the Buildkite artifact store, then
# copies the relevant files into artifacts/:
#   - Binary packages (.tar.gz, .zip, .deb, .rpm) from build/distributions/
#   - Dependency report CSV from build/distributions/reports/
#     (SNAPSHOT-named for snapshot workflow, non-SNAPSHOT for staging)
#
# Required env variables:
#   DRA_WORKFLOW  - "snapshot" or "staging"
#
# Required Buildkite artifacts (uploaded by prior build steps):
#   build/distributions/*
#   build/distributions/reports/*.csv
set -euo pipefail

WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"

echo "--- :compression: Downloading ${WORKFLOW} artifacts"

mkdir -p build/distributions/reports/

# Buildkite's "**" needs at least one directory, so the top-level binaries
# and the reports are fetched separately.
buildkite-agent artifact download "build/distributions/*" .
buildkite-agent artifact download "build/distributions/reports/*.csv" .

if ls build/distributions/* 1>/dev/null 2>&1; then
  chmod -R a+r build/distributions/
fi

echo "--- :package: Staging ${WORKFLOW} artifacts"
mkdir -p artifacts

# Release branches build both workflows in one build: snapshot files have
# "-SNAPSHOT" in the name, staging ones don't.
if [[ "${WORKFLOW}" == "snapshot" ]]; then
  name_filter=(-name "*-SNAPSHOT*")
else
  name_filter=(! -name "*-SNAPSHOT*")
fi

# Copy all binaries (tar.gz, zip, deb, rpm) and their checksums
find build/distributions -maxdepth 1 -type f \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.deb" -o -name "*.rpm" -o -name "*.sha512" \) \
  "${name_filter[@]}" -exec cp {} artifacts/ \;

# Copy the dependency report CSV
find build/distributions/reports -maxdepth 1 -type f -name "*.csv" "${name_filter[@]}" -exec cp {} artifacts/ \;

binaries=$(find artifacts -maxdepth 1 -type f ! -name "*.csv" ! -name "*.sha512" | wc -l)
reports=$(find artifacts -maxdepth 1 -type f -name "*.csv" | wc -l)
if [[ "${binaries}" -eq 0 || "${reports}" -ne 1 ]]; then
  echo "ERROR: expected ${WORKFLOW} binaries and one dependency report, found ${binaries} binaries and ${reports} reports." >&2
  exit 1
fi

# Generate checksum for the dependency report CSV
(cd artifacts && for f in *.csv; do sha512sum "$f" > "$f.sha512"; done)

echo "Staged artifacts:"
ls -1 artifacts/

#!/bin/bash

# Downloads and merges coverage files from multiple steps into a single file (build/TEST-go-unit.cov).
# Usage: merge.sh <step1> <step2> ... Where <step> is the id of the step that contains the coverage artifact.#
set -euo pipefail
set -x # for debugging

MERGED_COV_FILE="TEST-go-unit.cov"

go install github.com/wadey/gocovmerge@latest

buildkite-agent artifact download "coverage-*.cov"
# Space separated list of paths to coverage files
COV_PATHS=$(find "coverage-*.cov" -print0 )
gocovmerge "$COV_PATHS" > "$MERGED_COV_FILE"
echo "Merged coverage file: $MERGED_COV_FILE. See artifacts"

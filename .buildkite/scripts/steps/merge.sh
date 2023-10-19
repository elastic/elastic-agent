#!/bin/bash

# Downloads and merges coverage files from multiple steps into a single file (build/TEST-go-unit.cov).
# Usage: merge.sh <step1> <step2> ... Where <step> is the id of the step that contains the coverage artifact.#  

set -exuo pipefail

COV_FILE="build/TEST-go-unit.cov"
# Space separated list of paths to coverage files
COV_PATHS=""

go install github.com/wadey/gocovmerge@latest
mkdir -p build

for STEP_ID in "$@"; do
  mkdir -p $STEP_ID 
  buildkite-agent artifact download --step $STEP_ID $COV_FILE $STEP_ID
  COV_PATHS="${COV_PATHS} $STEP_ID/$COV_FILE"
done

gocovmerge $COV_PATHS > $COV_FILE
echo "Merged coverage file: $COV_FILE. See artifacts"
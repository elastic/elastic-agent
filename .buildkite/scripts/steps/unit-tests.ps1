$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"

Write-Host "--- Unit tests"
$env:TEST_COVERAGE = $true
# The race detector is disabled on:
#   - ARM64: the Go race detector is not supported on windows/arm64.
#   - Windows 11 amd64 (DISABLE_RACE_DETECTOR set by the pipeline step): running
#     the unit tests under -race reliably triggers a Go runtime GC-metadata
#     corruption crash that is specific to this platform. The tests are otherwise
#     healthy, so we keep them running without -race rather than skipping them.
#     See https://github.com/elastic/elastic-agent/issues/14248
if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64" -and $env:DISABLE_RACE_DETECTOR -ne "true") {
  $env:RACE_DETECTOR = $true
}
mage unitTest
# Copy coverage file to build directory so it can be downloaded as an artifact
Write-Host "--- Prepare artifacts"
$buildkiteJobId = $env:BUILDKITE_JOB_ID
Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"
if ($LASTEXITCODE -ne 0) {
  exit 1
}



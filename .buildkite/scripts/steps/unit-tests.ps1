$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"

Write-Host "--- Unit tests"
$env:TEST_COVERAGE = $true
if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") {
  $env:RACE_DETECTOR = $true
}
# Diagnostic: verify asyncpreemptoff=1 also prevents the panic on Windows 11
# (previous confirmation was on Windows 2025 only). GOFLAGS=-count=999999 runs
# each test repeatedly until the binary crashes; the job will either fail when
# the corruption manifests or run until the CI timeout. If all 3 jobs survive,
# asyncpreemptoff=1 is confirmed to suppress the bug on Windows 11 as well.
$env:GODEBUG = "asyncpreemptoff=1"
$env:GOTRACEBACK = "crash"
$env:GOFLAGS = "-count=999999"
mage unitTest
# Copy coverage file to build directory so it can be downloaded as an artifact
Write-Host "--- Prepare artifacts"
$buildkiteJobId = $env:BUILDKITE_JOB_ID
Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"
if ($LASTEXITCODE -ne 0) {
  exit 1
}



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
# Diagnostic: maximize GC pressure to make golang/go#77975 more consistent.
# GOGC=1 triggers a GC cycle after every allocation, maximising shrinkstack and
# scanstack frequency. This forces the kernel's async IOCP write (which targets
# a goroutine-stack-allocated variable) to race against far more stack
# relocations per second, making the memory-corruption crash far more likely
# without suppressing the bug like asyncpreemptoff=1 does.
# GOFLAGS=-count=999999 keeps each job looping until it crashes or times out.
$env:GOGC = "1"
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


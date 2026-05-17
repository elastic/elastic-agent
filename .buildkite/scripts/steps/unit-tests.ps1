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
# Loop over fresh binary invocations instead of -count: the crash is most
# likely at binary startup when goroutine stacks are freshly allocated.
$env:GOGC = "1"
$env:GOTRACEBACK = "crash"
$env:GODEBUG = "clobberfree=1,gccheckmark=1,invalidptr=1,cgocheck=2,gctrace=1,asyncpreemptoff=1"

$maxRuns = 5
for ($run = 1; $run -le $maxRuns; $run++) {
  Write-Host "--- Unit test run $run of $maxRuns"
  mage unitTest
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Test binary exited with code $LASTEXITCODE on run $run"
    Write-Host "--- Prepare artifacts"
    $buildkiteJobId = $env:BUILDKITE_JOB_ID
    if (Test-Path "build/TEST-go-unit.cov") {
      Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
    }
    if (Test-Path "build/TEST-go-unit.xml") {
      Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"
    }
    exit $LASTEXITCODE
  }
}

# Copy artifacts from the final run
Write-Host "--- Prepare artifacts"
$buildkiteJobId = $env:BUILDKITE_JOB_ID
Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"


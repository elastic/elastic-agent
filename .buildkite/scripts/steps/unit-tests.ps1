$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"

Write-Host "--- Build unit test helper binaries"
# Some unit tests exec helper binaries (pkg/component/fake/component,
# internal/edot/testing, ...).  `go test ./...` will not build them on its own,
# so reuse the existing mage target for prep.
mage build:unitTestBinaries
if ($LASTEXITCODE -ne 0) {
  Write-Host "build:unitTestBinaries failed with $LASTEXITCODE"
  exit $LASTEXITCODE
}

Write-Host "--- Unit tests"
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
$env:GODEBUG = "clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1"
$env:GOEXPERIMENT="cgocheck2"

# Bypass `mage unitTest` / gotestsum.  gotestsum (v1.13) treats every non-JSON
# line on the test process's stderr as a "package error", so gctrace=1 produces
# thousands of spurious failures, and its default 64 KB bufio scanner trips on
# the goroutine dumps GOTRACEBACK=crash emits ("token too long").  This is a
# diagnostic run that exists to reproduce a runtime crash; JUnit reporting is
# not useful here, and the raw `go test -v` output is easier to correlate with
# the gctrace lines anyway.
$testArgs = @("test", "-count=1", "-v", "-timeout=20m")
if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") {
  $testArgs += "-race"
}
$testArgs += @(
  "-covermode=atomic",
  "-coverprofile=build/coverage.out",
  "-coverpkg=./...",
  "./..."
)

# Patterns that indicate the Go runtime tripped a sanity check or crashed
# mid-GC (the bug we're hunting).  Normal test failures - t.Fatal, assertion
# mismatches, even user-level panics - do NOT match these.  This script's whole
# purpose is to catch those runtime crashes, so the job is treated as "passing"
# unless one of these markers shows up.
$crashRegex = 'runtime: marked free object|runtime: found pointer to free object|fatal error: '
$crashed = $false

New-Item -ItemType Directory -Force -Path "build" | Out-Null
$runLog = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "build\test-output.log"

$maxRuns = 5
for ($run = 1; $run -le $maxRuns; $run++) {
  Write-Host "--- Unit test run $run of $maxRuns"
  & go @testArgs 2>&1 | Tee-Object -FilePath $runLog -Append
  Write-Host "go test exited with code $LASTEXITCODE on run $run"

  if (Select-String -Path $runLog -Pattern $crashRegex -Quiet) {
    Write-Host "*** Runtime crash marker detected on run $run - stopping further runs ***"
    $crashed = $true
    break
  }
}

Write-Host "--- Prepare artifacts"
$buildkiteJobId = $env:BUILDKITE_JOB_ID
if (Test-Path "build/coverage.out") {
  Move-Item -Path "build/coverage.out" -Destination "coverage-$buildkiteJobId.out"
}

if ($crashed) {
  Write-Host "Runtime crash reproduced - failing job."
  exit 1
} else {
  Write-Host "No runtime crash across $maxRuns runs - passing job (unrelated test failures are ignored)."
  exit 0
}


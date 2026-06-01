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

# --- Mitigation handling -----------------------------------------------------
# The earlier `Set-ProcessMitigation -System` approach was a no-op without a
# reboot: the system default lives in Session Manager\kernel\MitigationOptions
# and is read at boot, so build 40690's bisect + child-posture probe showed the
# test processes kept their DEFAULT posture in every arm (BottomUp stayed ON;
# UserShadowStack was OFF only because CET is off by default). The only
# no-reboot lever is per-image IFEO (`Set-ProcessMitigation -Name <exe>`), which
# is applied at process creation. DISABLE_MITIGATIONS_IFEO=1 applies it to every
# test binary by image name (<import-path-leaf>.test.exe).
$ifeoNames = @()
if ($env:DISABLE_MITIGATIONS_IFEO -eq "1") {
  Write-Host "--- Disabling mitigations per test-binary via IFEO (no reboot needed)"
  $mits = @("HighEntropy", "BottomUp", "ForceRelocateImages", "UserShadowStack")
  # IFEO matches on the image's base name regardless of the temp path go test
  # runs it from. Enumerate both modules (root + internal/edot).
  foreach ($mod in @("", "internal\edot")) {
    $listArgs = @("list"); if ($mod) { $listArgs += @("-C", $mod) }; $listArgs += "./..."
    $prevEAP = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { $pkgs = & go @listArgs 2>$null } finally { $ErrorActionPreference = $prevEAP }
    foreach ($p in $pkgs) { $ifeoNames += (($p -split '/')[-1] + ".test.exe") }
  }
  $ifeoNames = $ifeoNames | Sort-Object -Unique
  Write-Host "Applying IFEO mitigation-disable to $($ifeoNames.Count) test-binary names"
  foreach ($exe in $ifeoNames) {
    try { Set-ProcessMitigation -Name $exe -Disable $mits -ErrorAction Stop } catch { Write-Host "  IFEO set failed for ${exe}: $_" }
  }
  # Verify the override is configured AND effective without a reboot: build one
  # test binary, launch it, and read its per-process posture.
  try {
    $cfg = Get-ProcessMitigation -Name "upgrade.test.exe"
    Write-Host ("IFEO config(upgrade.test.exe): BottomUp={0} HighEntropy={1} ForceRelocate={2} UserShadowStack={3}" -f `
      $cfg.ASLR.BottomUp, $cfg.ASLR.HighEntropy, $cfg.ASLR.ForceRelocateImages, $cfg.UserShadowStack.UserShadowStack)
    $probeExe = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "upgrade.test.exe"
    $prevEAP = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { & go test -c -o $probeExe ./internal/pkg/agent/application/upgrade/ 2>$null } finally { $ErrorActionPreference = $prevEAP }
    if (Test-Path $probeExe) {
      $pp = Start-Process $probeExe -ArgumentList '-test.run=^NoSuchTest$','-test.timeout=20s' -PassThru -WindowStyle Hidden
      Start-Sleep -Milliseconds 500
      try {
        $pm = Get-ProcessMitigation -Id $pp.Id
        Write-Host ("EFFECTIVE posture(upgrade.test.exe pid=$($pp.Id)): ASLR.BottomUp={0} | UserShadowStack={1}" -f $pm.ASLR.BottomUp, $pm.UserShadowStack.UserShadowStack)
      } catch { Write-Host "effective posture probe failed (process may have exited): $_" }
      try { Wait-Process -Id $pp.Id -Timeout 25 -ErrorAction SilentlyContinue } catch {}
    }
  } catch { Write-Host "IFEO verification probe failed: $_" }
} else {
  # Control / norace: leave mitigations at default; just record the baseline so
  # every run documents the posture it actually ran with.
  try {
    $probe = Start-Process powershell -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 2' -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 300
    $pm = Get-ProcessMitigation -Id $probe.Id
    Write-Host ("baseline posture(child pid=$($probe.Id)): ASLR.BottomUp={0} | UserShadowStack={1}" -f `
      $pm.ASLR.BottomUp, $pm.UserShadowStack.UserShadowStack)
  } catch { Write-Host "baseline posture probe failed: $_" }
}

Write-Host "--- Unit tests"
# Diagnostic: maximize GC pressure to make the crash more consistent. GOGC=1
# triggers a GC cycle after every allocation, maximising scanstack/shrinkstack/
# copystack frequency - the crash manifests as GC mark-metadata corruption
# detected during a stack scan, so more GC cycles = more chances to hit it.
# (The original IOCP-async-write theory / golang/go#77975 is ruled out: the
# tests' file I/O is synchronous on Windows, so there is no post-syscall kernel
# write window. Mechanism is currently open.)
# Loop over fresh binary invocations instead of -count: the crash is most
# likely at binary startup when goroutine stacks are freshly allocated.
# GOGC=1 forces a GC after every allocation, which AMPLIFIES the crash (more
# mark/scan cycles = more chances to hit + detect the corruption). GOGC_DEFAULT=1
# leaves GOGC at its default (100) to test whether that amplification is
# *required* or merely a catalyst: the sanity-check GODEBUGs (gccheckmark,
# invalidptr) are kept either way, so a crash is still detected if it fires - we
# just stop forcing constant GC. If the gogc-default cohort still crashes (even
# at a lower rate), GC-pressure is an amplifier, not a prerequisite.
if (-not $env:GOGC_DEFAULT) {
  $env:GOGC = "1"
}
Write-Host "GOGC=$($env:GOGC)"
$env:GOTRACEBACK = "crash"
$baseGodebug = "clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1"
# Optional extra GODEBUG knobs injected by the pipeline.
if ($env:EXTRA_GODEBUG) {
  $env:GODEBUG = "$baseGodebug,$env:EXTRA_GODEBUG"
} else {
  $env:GODEBUG = $baseGodebug
}
Write-Host "GODEBUG=$env:GODEBUG"

# GOEXPERIMENT is baked into the runtime/std `go test` rebuilds. cgocheck2 adds
# stricter cgo pointer-passing checks. EXTRA_GOEXPERIMENT lets a pipeline
# variant inject further experiments without editing this script. (Green Tea GC
# was ruled out as the cause - the crash reproduces with nogreenteagc and on Go
# 1.25.10 - so no variant currently sets it, but the lever is kept for future
# A/Bs.)
$baseGoexperiment = "cgocheck2"
if ($env:EXTRA_GOEXPERIMENT) {
  $env:GOEXPERIMENT = "$baseGoexperiment,$env:EXTRA_GOEXPERIMENT"
} else {
  $env:GOEXPERIMENT = $baseGoexperiment
}
Write-Host "GOEXPERIMENT=$env:GOEXPERIMENT"

# Bypass `mage unitTest` / gotestsum.  gotestsum (v1.13) treats every non-JSON
# line on the test process's stderr as a "package error", so gctrace=1 produces
# thousands of spurious failures, and its default 64 KB bufio scanner trips on
# the goroutine dumps GOTRACEBACK=crash emits ("token too long").  This is a
# diagnostic run that exists to reproduce a runtime crash; JUnit reporting is
# not useful here, and the raw `go test -v` output is easier to correlate with
# the gctrace lines anyway.
$testArgs = @("test", "-count=1", "-v", "-timeout=20m")
# The race detector is only supported on windows/amd64 (never arm64), so arm64
# is implicitly -race-off.  The NO_RACE pipeline variant disables it on amd64
# too, to test whether the race detector's instrumentation/scheduling timing is
# required to surface the crash - if amd64 still crashes without -race, the bug
# is independent of the race detector.
$useRace = ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") -and (-not $env:NO_RACE)
if ($useRace) {
  $testArgs += "-race"
}
Write-Host "race detector enabled: $useRace"
# TEST_PKG narrows the package set (default the whole suite ./...). The full
# suite runs ~GOMAXPROCS package binaries concurrently, which self-generates the
# in-guest contention that makes the crash consistent; narrowing the set reduces
# that concurrency. Used to bisect gently from ./... downward while watching the
# crash-consistency gradient.
$testTarget = if ($env:TEST_PKG) { $env:TEST_PKG } else { "./..." }
Write-Host "test target: $testTarget"
# Coverage: -coverpkg=./... instruments every package, producing very large
# coverage-counter globals (the ~243 KB data-segment root the checkmark crash
# was scanning when it found the corrupt pointer). NO_COVER=1 drops all coverage
# flags to test whether that instrumentation footprint is a cofactor: if the
# no-cover cohort still crashes at the control's rate, coverage is irrelevant;
# if it stops, the coverage globals (or the cover tool's instrumentation) matter.
if ($env:NO_COVER) {
  Write-Host "coverage: DISABLED (NO_COVER)"
  $testArgs += $testTarget
} else {
  $testArgs += @(
    "-covermode=atomic",
    "-coverprofile=build/coverage.out",
    "-coverpkg=./...",
    $testTarget
  )
}

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
  # Windows PowerShell 5.1 wraps every stderr line from a native command
  # routed through `2>&1` as a RemoteException ErrorRecord.  With the
  # script-level `$ErrorActionPreference = "Stop"`, the very first such line
  # (a gctrace line under GODEBUG=gctrace=1) aborts the script before
  # Tee-Object ever runs.  Relax EAP just for the duration of the `go test`
  # call so the stderr stream is treated as text, not errors.
  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & go @testArgs 2>&1 | Tee-Object -FilePath $runLog -Append
  } finally {
    $ErrorActionPreference = $prevEAP
  }
  Write-Host "go test exited with code $LASTEXITCODE on run $run"

  if (Select-String -Path $runLog -Pattern $crashRegex -Quiet) {
    Write-Host "*** Runtime crash marker detected on run $run - stopping further runs ***"
    $crashed = $true
    break
  }
}

# Remove the IFEO overrides we added, so leftover registry state can't leak to a
# later job if this agent is reused (no-op on ephemeral agents; cheap insurance).
if ($ifeoNames.Count -gt 0) {
  Write-Host "--- Removing $($ifeoNames.Count) IFEO mitigation overrides"
  foreach ($exe in $ifeoNames) {
    try { Set-ProcessMitigation -Name $exe -Remove -ErrorAction Stop } catch {}
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


$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"

# --- Configure Windows Error Reporting to capture full crash dumps ---
# Requires the buildkite agent to run as Administrator (it does on these images).
# DumpType=2 = full memory dump (~50-200 MB per process). DumpCount=3 caps disk use.
# Snapshot the current LocalDumps values so we can restore them in the finally block;
# on shared (non-ephemeral) agents we don't want to leave the global key changed.
$dumpDir = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "build\dumps"
New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
$werKey = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
$werKeyExisted = Test-Path $werKey
$werPriorFolder = $null; $werPriorType = $null; $werPriorCount = $null
if ($werKeyExisted) {
    try { $werPriorFolder = (Get-ItemProperty -Path $werKey -Name DumpFolder -ErrorAction Stop).DumpFolder } catch {}
    try { $werPriorType   = (Get-ItemProperty -Path $werKey -Name DumpType   -ErrorAction Stop).DumpType }   catch {}
    try { $werPriorCount  = (Get-ItemProperty -Path $werKey -Name DumpCount  -ErrorAction Stop).DumpCount }  catch {}
} else {
    New-Item -Path $werKey -Force | Out-Null
}
Set-ItemProperty -Path $werKey -Name "DumpFolder" -Value $dumpDir -Type ExpandString
Set-ItemProperty -Path $werKey -Name "DumpType"   -Value 2 -Type DWord
Set-ItemProperty -Path $werKey -Name "DumpCount"  -Value 3 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontShowUI" -Value 1 -Type DWord
Write-Host "WER LocalDumps configured: DumpFolder=$dumpDir DumpType=2 (full) DumpCount=3"

$mageExit = 0
try {
    Write-Host "--- Build"
    mage build
    if ($LASTEXITCODE -ne 0) { $mageExit = 1; return }

    Write-Host "--- Unit tests (instrumented; asyncpreemptoff NOT set so the bug fires)"
    $env:TEST_COVERAGE = $true
    if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") {
        $env:RACE_DETECTOR = $true
    }
    # Instrumentation:
    # - clobberfree=1: paints freed heap memory with 0xdead pattern so corrupted bytes
    #   in the GC dump are recognizable as "freed memory leaked into use" vs random junk.
    # - gctrace=1: one line per GC cycle on stderr; helps correlate the crashing sweep.
    # - schedtrace=10000: scheduler state every 10s; shows what was running on which M/P.
    # - GOTRACEBACK=crash: full goroutine traceback to stderr THEN raises SIGABRT, so WER
    #   captures the dump.
    # Loop over fresh binary invocations (same reason as the diagnostic script: the crash
    # is most likely at binary startup; -count loops accumulate heap and OOM instead).
    $env:GODEBUG = "clobberfree=1,gctrace=1,schedtrace=10000"
    $env:GOTRACEBACK = "crash"

    $maxRuns = 5
    for ($run = 1; $run -le $maxRuns; $run++) {
        Write-Host "--- Unit test run $run of $maxRuns"
        mage unitTest
        $mageExit = $LASTEXITCODE
        if ($mageExit -ne 0) {
            Write-Host "Test binary exited with code $mageExit on run $run"
            break
        }
    }

    Write-Host "--- Prepare artifacts"
    $buildkiteJobId = $env:BUILDKITE_JOB_ID
    if (Test-Path "build/TEST-go-unit.cov") {
        Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
    }
    if (Test-Path "build/TEST-go-unit.xml") {
        Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"
    }
    $dumps = Get-ChildItem -Path $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue
    if ($dumps) {
        Write-Host "Captured $($dumps.Count) crash dump(s):"
        $dumps | ForEach-Object { Write-Host "  $($_.FullName) ($([math]::Round($_.Length/1MB,1)) MB)" }
    } else {
        Write-Host "No crash dumps captured (test suite did not crash, or WER did not fire)."
    }
} finally {
    # Restore WER LocalDumps to its pre-job state so we don't leak global config to
    # whatever job runs on this agent next (no-op on ephemeral agents but cheap insurance).
    if ($werKeyExisted) {
        if ($null -ne $werPriorFolder) {
            Set-ItemProperty -Path $werKey -Name "DumpFolder" -Value $werPriorFolder -Type ExpandString
        } else {
            Remove-ItemProperty -Path $werKey -Name "DumpFolder" -ErrorAction SilentlyContinue
        }
        if ($null -ne $werPriorType) {
            Set-ItemProperty -Path $werKey -Name "DumpType" -Value $werPriorType -Type DWord
        } else {
            Remove-ItemProperty -Path $werKey -Name "DumpType" -ErrorAction SilentlyContinue
        }
        if ($null -ne $werPriorCount) {
            Set-ItemProperty -Path $werKey -Name "DumpCount" -Value $werPriorCount -Type DWord
        } else {
            Remove-ItemProperty -Path $werKey -Name "DumpCount" -ErrorAction SilentlyContinue
        }
    } else {
        Remove-Item -Path $werKey -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "WER LocalDumps restored."
}

exit $mageExit

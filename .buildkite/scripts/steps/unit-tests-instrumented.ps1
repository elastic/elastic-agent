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

$crashed = $false
try {
    Write-Host "--- Build unit test helper binaries"
    # Some unit tests exec helper binaries (pkg/component/fake/component,
    # internal/edot/testing, ...).  `go test ./...` will not build them on its
    # own, so reuse the existing mage target for prep.
    mage build:unitTestBinaries
    if ($LASTEXITCODE -ne 0) {
        Write-Host "build:unitTestBinaries failed with $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host "--- Unit tests (instrumented; asyncpreemptoff NOT set so the bug fires)"
    # Instrumentation:
    # - clobberfree=1: paints freed heap memory with 0xdead pattern so corrupted bytes
    #   in the GC dump are recognizable as "freed memory leaked into use" vs random junk.
    # - gctrace=1: one line per GC cycle on stderr; correlates the crashing sweep.
    # - schedtrace=10000: scheduler state every 10s; shows what was running on which M/P.
    # - GOTRACEBACK=crash: full goroutine traceback to stderr THEN raises SIGABRT, so WER
    #   captures the dump.
    $env:GODEBUG = "clobberfree=1,gctrace=1,schedtrace=10000"
    $env:GOTRACEBACK = "crash"

    # We deliberately bypass `mage unitTest` / gotestsum here.  gotestsum (v1.13)
    # treats every non-JSON line on the test process's stderr as a "package
    # error", which means gctrace=1 (one line per GC cycle, thousands per run)
    # produces a giant tally of spurious failures and masks the real signal.
    # It also uses a default 64 KB bufio scanner that trips on the large
    # goroutine dumps GOTRACEBACK=crash emits when the bug fires ("token too
    # long").  This is a diagnostic run that exists to crash the binary so WER
    # can capture a dump; we don't need JUnit, and the raw `go test -v` output
    # is easier to correlate with the gctrace/schedtrace lines anyway.
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
    # mismatches, even user-level panics - do NOT match these.  This script's
    # whole purpose is to catch those runtime crashes, so the job is treated as
    # "passing" unless one of these markers shows up (a runtime crash is what
    # we want to surface; everything else is unrelated noise).
    $crashRegex = 'runtime: marked free object|runtime: found pointer to free object|fatal error: '

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
    $dumps = Get-ChildItem -Path $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue
    if ($dumps) {
        Write-Host "Captured $($dumps.Count) crash dump(s):"
        $dumps | ForEach-Object { Write-Host "  $($_.FullName) ($([math]::Round($_.Length/1MB,1)) MB)" }
        # A WER dump is also a real crash, regardless of whether we matched a
        # text marker (the Go runtime may exit before its diagnostic prints
        # flush all the way through Tee-Object).
        $crashed = $true
    } elseif (-not $crashed) {
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

if ($crashed) {
    Write-Host "Runtime crash reproduced - failing job."
    exit 1
} else {
    Write-Host "No runtime crash across $maxRuns runs - passing job (unrelated test failures are ignored)."
    exit 0
}

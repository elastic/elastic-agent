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

# --- Register procdump as AeDebug postmortem debugger ---
# WER LocalDumps alone is not enough on Go programs: Go's runtime installs an
# UnhandledExceptionFilter that prints its own panic trace and exits cleanly,
# so the exception never becomes "unhandled" from WER's perspective.  Procdump
# registered via AeDebug runs *before* the UEF and grabs a dump anyway.
$procdumpInstalled = $false
$toolsDir = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "build\tools"
$procdumpExe = Join-Path $toolsDir "procdump64.exe"
try {
    if (-not (Test-Path $procdumpExe)) {
        New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
        $zip = Join-Path $env:TEMP "procdump.zip"
        Write-Host "Downloading Sysinternals procdump..."
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $toolsDir -Force
        Remove-Item $zip -ErrorAction SilentlyContinue
    }
    # -accepteula avoids the interactive prompt the first time procdump is run.
    # -ma writes a full memory dump.  -i <dir> installs procdump as the AeDebug
    # postmortem debugger; subsequent unhandled exceptions in any process on
    # this agent will trigger procdump and the dump lands in $dumpDir.
    & $procdumpExe -accepteula -ma -i $dumpDir
    if ($LASTEXITCODE -eq 0) {
        $procdumpInstalled = $true
        Write-Host "procdump installed as AeDebug postmortem debugger (dumps -> $dumpDir)"
    } else {
        Write-Host "WARNING: procdump install failed with exit $LASTEXITCODE (continuing without binary dumps)"
    }
} catch {
    Write-Host "WARNING: procdump setup failed: $_ (continuing without binary dumps)"
}

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
    # -work keeps go test's per-package temp directories (b001/, b002/, ...)
    # after the run completes.  Each contains the compiled <pkg>.test.exe; we
    # need those preserved so that whichever test binaries crashed can be
    # uploaded alongside their dumps for symbol resolution in dlv/WinDbg.
    $testArgs = @("test", "-count=1", "-v", "-work", "-timeout=20m")
    if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") {
        $testArgs += "-race"
    }
    # Wrap each test binary launch with procdump.  -e 1 enables first-chance
    # exception capture - critical for Go binaries because Go's runtime handles
    # exceptions in its UnhandledExceptionFilter and the second-chance never
    # fires (so AeDebug alone is not enough).  -ma writes a full memory dump.
    # The wrapper is passed to `go test` via -exec; go test then invokes it as
    # `<wrapper> <test-binary> <test-args>`, which procdump consumes as
    # `procdump -ma -e 1 -accepteula -x <dumpDir> <test-binary> <test-args>`.
    if ($procdumpInstalled) {
        $execValue = "`"$procdumpExe`" -ma -e 1 -accepteula -x `"$dumpDir`""
        $testArgs += "-exec=$execValue"
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
        # Windows PowerShell 5.1 wraps every stderr line from a native command
        # routed through `2>&1` as a RemoteException ErrorRecord.  With the
        # script-level `$ErrorActionPreference = "Stop"`, the very first such
        # line (a SCHED trace from compilation under schedtrace=10000) aborts
        # the script before Tee-Object ever runs.  Relax EAP just for the
        # duration of the `go test` call so the stderr stream is treated as
        # text, not errors.
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

        # Copy the matching test binary for each dump so dlv/WinDbg can resolve
        # symbols (function names, line numbers).  Binaries are 200+ MB each
        # with -race + -coverpkg=./..., so we copy ONLY the ones that crashed
        # rather than every test binary in the work tree.
        $binsDir = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "build\bins"
        New-Item -ItemType Directory -Force -Path $binsDir | Out-Null
        # go test -work creates a fresh `go-build<N>` directory per invocation
        # under GOTMPDIR.  Restrict the search to those so we never pick up a
        # stale binary from a different mage/build step.  For each matching
        # name we then pick the LARGEST file - the race+coverage instrumented
        # test binary is consistently the biggest by a wide margin, so this
        # cleanly filters out earlier-stage compiles that may share the name.
        $workDirs = Get-ChildItem -Path $env:GOTMPDIR -Filter "go-build*" -Directory -ErrorAction SilentlyContinue
        foreach ($dump in $dumps) {
            if ($dump.Name -match '^(.+\.exe)_\d+_\d+\.dmp$') {
                $binName = $Matches[1]
                $candidates = @()
                foreach ($wd in $workDirs) {
                    $candidates += Get-ChildItem -Path $wd.FullName -Recurse -Filter $binName -File -ErrorAction SilentlyContinue
                }
                $found = $candidates | Sort-Object Length -Descending | Select-Object -First 1
                if ($found) {
                    $dest = Join-Path $binsDir $binName
                    Copy-Item -Path $found.FullName -Destination $dest -Force
                    Write-Host "  Saved binary for $binName ($([math]::Round($found.Length/1MB,1)) MB) from $($found.FullName)"
                } else {
                    Write-Host "  WARNING: could not find $binName under any go-build* dir in $env:GOTMPDIR"
                }
            }
        }
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

    # Unregister procdump as AeDebug so we don't leave global state pointing
    # at a build-scoped path the next job won't have.  `-u` is idempotent; if
    # install failed, the unregister no-ops.
    if ($procdumpInstalled -and (Test-Path $procdumpExe)) {
        & $procdumpExe -u
        Write-Host "procdump uninstalled."
    }
}

if ($crashed) {
    Write-Host "Runtime crash reproduced - failing job."
    exit 1
} else {
    Write-Host "No runtime crash across $maxRuns runs - passing job (unrelated test failures are ignored)."
    exit 0
}

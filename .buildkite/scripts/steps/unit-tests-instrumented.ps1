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

    # Two GODEBUG modes:
    #  - default (instrumented): a light config that lets the bug fire naturally;
    #    in practice it tends to yield the sweep-phase "found pointer to free
    #    object" crash, whose FailFast record carries only ExceptionCode 2.
    #  - DIAG_CAPTURE=1: the diagnostic config (GOGC=1 + gccheckmark + invalidptr
    #    + asyncpreemptoff). This maximises the *in-the-act* signatures we lack a
    #    dump of: "checkmark found unmarked object" and "unexpected signal during
    #    runtime execution" (a GC stack-scan access violation). Those are
    #    AV-origin crashes, so dieFromException reconstructs the FailFast record
    #    from gp.sig and the dump carries the real 0xC0000005 code + faulting PC +
    #    fault address. Same proven capture path either way.
    # clobberfree=1 paints freed heap with 0xdead so corrupted bytes stand out;
    # gctrace=1 = one line per GC; GOTRACEBACK=crash = full traceback then crash.
    if ($env:DIAG_CAPTURE -eq "1") {
        Write-Host "--- Unit tests (DIAG_CAPTURE: diagnostic GODEBUG + dump capture)"
        $env:GOGC = "1"
        $env:GODEBUG = "clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1"
        $env:GOEXPERIMENT = "cgocheck2"
    } else {
        Write-Host "--- Unit tests (instrumented; asyncpreemptoff NOT set so the bug fires)"
        $env:GODEBUG = "clobberfree=1,gctrace=1,schedtrace=10000"
    }
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
    # Wrap each test binary launch with procdump.  -ma = full memory dump.
    # -e 1 = also monitor first-chance exceptions; -f Breakpoint filters *those*
    # so we do NOT dump on the many benign first-chance AVs Go's fmt machinery
    # raises probing nil Stringer pointers.
    #
    # The fatal crash is captured regardless of -f: Go's crash() ->
    # dieFromException raises it via RaiseFailFastException (a noncontinuable,
    # handler-bypassing exception - NOT an INT 3; it shows up in the dump with
    # ExceptionAddress inside asmstdcall and, for a plain throw, the synthetic
    # ExceptionCode 2). procdump captures that terminating exception as the
    # process dies. So -f Breakpoint means "ignore benign first-chance noise,
    # still grab the fatal FailFast".
    #
    # go test -exec invokes: procdump -ma -e 1 -f Breakpoint -accepteula -x <dumpDir> <test-binary> <test-args>.
    if ($procdumpInstalled) {
        $execValue = "`"$procdumpExe`" -ma -e 1 -f Breakpoint -accepteula -x `"$dumpDir`""
        $testArgs += "-exec=$execValue"
    }
    # TEST_RUN narrows to a subset of tests (passed as -run) to bisect which
    # test cases are necessary to trigger the crash.
    if ($env:TEST_RUN) {
        $testArgs += "-run=$env:TEST_RUN"
        Write-Host "test filter: -run=$env:TEST_RUN"
    }
    # TEST_PKG scopes the run to one package (e.g. the upgrade package) so that
    # EVERY crash lands in a single, rebuildable test binary (<pkg>.test.exe) -
    # the whole-suite run scatters crashes into packages whose binaries can't be
    # rebuilt (e.g. the mage-target "test.test.exe"), leaving those dumps
    # unsymbolicable. Coverage flags are kept identical so the run binary and the
    # crash-time rebuild byte-match.
    $testTarget = if ($env:TEST_PKG) { $env:TEST_PKG } else { "./..." }
    Write-Host "test target: $testTarget"
    $testArgs += @(
        "-covermode=atomic",
        "-coverprofile=build/coverage.out",
        "-coverpkg=./...",
        $testTarget
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

    # Clear the diagnostic GODEBUG/GOTRACEBACK before any further `go`
    # invocations.  gctrace/schedtrace make every subsequent `go` command
    # (go list, go test -c) write trace lines to stderr, and with the
    # script-level $ErrorActionPreference = "Stop" PowerShell turns the first
    # such native-command stderr line into a terminating error - which is
    # what aborted the artifact-rebuild step in build 40519 before it ran.
    $env:GODEBUG = ""
    $env:GOTRACEBACK = ""
    # GOGC=1 (DIAG_CAPTURE mode) would make the rebuild compiler GC after every
    # allocation - cripplingly slow. Clear it. Leave GOEXPERIMENT set: the
    # rebuilt binary must use the same experiments to byte-match the dump.
    $env:GOGC = ""

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

        # Build a fresh symbol-rich test binary for each crashed package so
        # dlv/WinDbg can resolve symbols (function names, line numbers).  We
        # used to just copy the binary from go test -work's tree, but build
        # 40516 showed that artifact is stripped (no runtime.pclntab, no
        # DWARF) - presumably go test's internal flow rewrites the binary
        # after running, or the binary we picked was an intermediate compile.
        #
        # Instead, invoke `go test -c -o` with the same race/coverage flags
        # against the package that produced the dump.  The result is built
        # from the same source on the same Go toolchain on the same agent,
        # so function offsets line up with the dump - and we get full
        # symbols.  Building takes ~30-60s per crashed package; we accept
        # that as the cost of useful dumps.
        $binsDir = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "build\bins"
        New-Item -ItemType Directory -Force -Path $binsDir | Out-Null

        # Map a dump's binary basename (e.g. "upgrade" from upgrade.test.exe)
        # to a package import path so we can rebuild it.  This repo has more
        # than one Go module (the root module and internal/edot), and `go list
        # ./...` only sees the module it runs in - so we enumerate each module
        # and remember which module dir each package belongs to (needed for
        # `go test -C <dir>` at rebuild time).  Basenames are not unique
        # (e.g. several packages produce <x>.test); we keep every candidate and
        # try each until one actually compiles.  A package with no test files
        # produces no output from `go test -c`, so it's skipped naturally.
        #
        # Relax EAP around the native calls so stderr chatter (download
        # progress, build warnings) is not treated as terminating.
        $moduleDirs = @("", "internal\edot")
        $pkgCandidates = @()
        foreach ($mod in $moduleDirs) {
            $listArgs = @("list")
            if ($mod -ne "") { $listArgs += @("-C", $mod) }
            $listArgs += "./..."
            $prevEAP = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $pkgs = & go @listArgs 2>$null
            } finally {
                $ErrorActionPreference = $prevEAP
            }
            foreach ($p in $pkgs) {
                $pkgCandidates += [pscustomobject]@{ ImportPath = $p; ModuleDir = $mod; Base = (Split-Path $p -Leaf) }
            }
        }

        foreach ($dump in $dumps) {
            if ($dump.Name -notmatch '^(.+)\.test\.exe_\d+_\d+\.dmp$') {
                Write-Host "  WARNING: dump filename '$($dump.Name)' does not match the expected <pkg>.test.exe_*.dmp pattern; skipping"
                continue
            }
            $pkgBase = $Matches[1]
            $binName = "$pkgBase.test.exe"
            $dest = Join-Path $binsDir $binName

            $candMatches = @($pkgCandidates | Where-Object { $_.Base -eq $pkgBase })
            if ($candMatches.Count -eq 0) {
                Write-Host "  WARNING: no package in any module has basename '$pkgBase'; cannot rebuild $binName"
                continue
            }

            $built = $false
            foreach ($cand in $candMatches) {
                $compileArgs = @("test", "-c", "-covermode=atomic", "-coverpkg=./...", "-o", $dest)
                if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") {
                    $compileArgs += "-race"
                }
                if ($cand.ModuleDir -ne "") {
                    # -C changes go's working dir to the submodule before the
                    # rest of the args are interpreted; the -o path is absolute
                    # so output still lands in build\bins.
                    $compileArgs = @("-C", $cand.ModuleDir) + $compileArgs
                }
                $compileArgs += $cand.ImportPath

                $prevEAP = $ErrorActionPreference
                $ErrorActionPreference = "Continue"
                try {
                    Write-Host "  Compiling $binName from $($cand.ImportPath) (module '$($cand.ModuleDir)') ..."
                    & go @compileArgs 2>&1 | Out-Host
                } finally {
                    $ErrorActionPreference = $prevEAP
                }
                if (Test-Path $dest) {
                    $size = (Get-Item $dest).Length
                    Write-Host "  Saved binary for $binName ($([math]::Round($size/1MB,1)) MB) compiled from $($cand.ImportPath)"
                    $built = $true
                    break
                }
            }
            if (-not $built) {
                Write-Host "  WARNING: none of the $($candMatches.Count) candidate package(s) for '$pkgBase' produced a test binary: $(($candMatches | ForEach-Object { $_.ImportPath }) -join ', ')"
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

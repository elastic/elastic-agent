# Green Tea GC A/B reproduction harness for golang/go#77975.
#
# Run on an Azure Standard_D8s_v5 Windows 11 VM (the platform-ingest
# elastic-agent-windows-11-pro image) from the repo root, with Go 1.26.3 on
# PATH.  It loops the diagnostic test command with Green Tea GC ON (the 1.26
# default) and OFF (GOEXPERIMENT=nogreenteagc), counting how many iterations
# crash with a runtime corruption marker.  A clear asymmetry (ON crashes, OFF
# does not) confirms the agent's crashes are the Green Tea GC bug.
#
# Usage examples:
#   .\tmp\greentea-ab.ps1                       # full suite, both arms, 20 iters each
#   .\tmp\greentea-ab.ps1 -Scope upgrade        # just the upgrade package (faster)
#   .\tmp\greentea-ab.ps1 -Arm on -Iterations 50
#   .\tmp\greentea-ab.ps1 -Scope upgrade -Iterations 100
#
# Notes:
# - GOEXPERIMENT is compiled into the std/runtime that `go test` rebuilds, so
#   the two arms genuinely differ in collector. The first run of each arm pays
#   a one-time std rebuild.
# - We do NOT use gotestsum here (it mis-parses gctrace stderr); raw `go test`.
# - EAP is relaxed around `go test` because PowerShell turns native-command
#   stderr (the gctrace lines) into terminating errors otherwise.

[CmdletBinding()]
param(
    [ValidateSet("full", "upgrade")]
    [string]$Scope = "full",

    [ValidateSet("on", "off", "both")]
    [string]$Arm = "both",

    [int]$Iterations = 20,

    # Stop an arm as soon as it crashes (default) or keep going to measure rate.
    [switch]$MeasureRate
)

$ErrorActionPreference = "Stop"
$env:GOTMPDIR = $PWD.Path

# Package selection.
if ($Scope -eq "upgrade") {
    $pkg = "./internal/pkg/agent/application/upgrade/"
} else {
    $pkg = "./..."
}

# Diagnostic env shared by both arms (mirrors .buildkite/scripts/steps/unit-tests.ps1).
$env:GOGC = "1"
$env:GOTRACEBACK = "crash"
$env:GODEBUG = "clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1"

$crashRegex = 'runtime: marked free object|found pointer to free object|fatal error:|Unlock of unlocked|allocCount|checkmark found unmarked'

$testArgs = @("test", "-count=1", "-timeout=20m")
if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") { $testArgs += "-race" }
$testArgs += @("-covermode=atomic", "-coverpkg=./...", $pkg)

function Run-Arm {
    param([string]$Name, [string]$Goexperiment)

    $env:GOEXPERIMENT = $Goexperiment
    Write-Host ""
    Write-Host "============================================================"
    Write-Host " ARM '$Name'  GOEXPERIMENT=$Goexperiment  scope=$Scope  iters=$Iterations"
    Write-Host "============================================================"

    $log = Join-Path $PSScriptRoot "greentea-$Name.log"
    Remove-Item $log -ErrorAction SilentlyContinue

    $crashes = 0
    for ($i = 1; $i -le $Iterations; $i++) {
        $stamp = (Get-Date).ToString("HH:mm:ss")
        Write-Host "--- [$Name] iteration $i/$Iterations ($stamp)"
        "=== [$Name] iteration $i ($stamp) GOEXPERIMENT=$Goexperiment ===" | Add-Content $log

        $iterLog = Join-Path $PSScriptRoot "greentea-$Name-iter.log"
        Remove-Item $iterLog -ErrorAction SilentlyContinue

        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & go @testArgs 2>&1 | Tee-Object -FilePath $iterLog | Add-Content $log
        } finally {
            $ErrorActionPreference = $prevEAP
        }
        $code = $LASTEXITCODE
        Write-Host "    go test exited $code"

        if (Select-String -Path $iterLog -Pattern $crashRegex -Quiet) {
            $crashes++
            $marker = (Select-String -Path $iterLog -Pattern $crashRegex | Select-Object -First 1).Line.Trim()
            Write-Host "    *** CRASH on [$Name] iter $i: $marker" -ForegroundColor Red
            if (-not $MeasureRate) {
                Write-Host "    (stopping arm '$Name' at first crash; pass -MeasureRate to continue)"
                break
            }
        }
    }

    Write-Host "ARM '$Name' result: $crashes crash(es) across the iterations run. Full log: $log"
    return $crashes
}

$onCrashes = $null
$offCrashes = $null
if ($Arm -eq "on" -or $Arm -eq "both") {
    $onCrashes = Run-Arm -Name "greenteaon" -Goexperiment "cgocheck2"
}
if ($Arm -eq "off" -or $Arm -eq "both") {
    $offCrashes = Run-Arm -Name "greenteaoff" -Goexperiment "cgocheck2,nogreenteagc"
}

Write-Host ""
Write-Host "==================== SUMMARY ===================="
if ($null -ne $onCrashes)  { Write-Host (" Green Tea ON  (default):       {0} crash(es)" -f $onCrashes) }
if ($null -ne $offCrashes) { Write-Host (" Green Tea OFF (nogreenteagc):  {0} crash(es)" -f $offCrashes) }
if (($null -ne $onCrashes) -and ($null -ne $offCrashes)) {
    if ($onCrashes -gt 0 -and $offCrashes -eq 0) {
        Write-Host " => CONFIRMS go#77975: disabling Green Tea GC suppresses the crash." -ForegroundColor Green
    } elseif ($onCrashes -gt 0 -and $offCrashes -gt 0) {
        Write-Host " => Green Tea GC NOT the (sole) cause: crashes persist with it off." -ForegroundColor Yellow
    } elseif ($onCrashes -eq 0) {
        Write-Host " => Did not reproduce even with Green Tea ON; increase -Iterations or use -Scope full." -ForegroundColor Yellow
    }
}

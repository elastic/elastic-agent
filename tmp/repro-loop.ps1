$ErrorActionPreference = "Continue"

$env:GODEBUG = "clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1"
$env:GOTRACEBACK = "crash"
$env:GOGC = "1"

$log = Join-Path $PSScriptRoot "repro-output.log"
Remove-Item $log -ErrorAction SilentlyContinue

$crashRegex = 'runtime: marked free object|found pointer to free object|fatal error:|Unlock of unlocked|allocCount'

$maxRuns = 100
for ($run = 1; $run -le $maxRuns; $run++) {
    $stamp = (Get-Date).ToString("HH:mm:ss")
    Write-Host "--- iteration $run/$maxRuns ($stamp)"
    "=== iteration $run ($stamp) ===" | Add-Content $log

    & go test -race -count=1 -timeout=20m `
        -run 'TestRollback|TestRollbackWithOpts|TestCleanup' `
        ./internal/pkg/agent/application/upgrade/ 2>&1 | Tee-Object -FilePath $log -Append

    $code = $LASTEXITCODE
    Write-Host "go test exited with $code on run $run"

    if (Select-String -Path $log -Pattern $crashRegex -Quiet) {
        Write-Host "*** RUNTIME CRASH MARKER detected on run $run ***"
        exit 1
    }
}
Write-Host "No runtime crash across $maxRuns runs."
exit 0

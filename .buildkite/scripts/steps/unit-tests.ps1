$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"

# === BEGIN debug/13796 instrumentation (revert when issue resolved) ===
# Make Go call abort() on fatal panics so Windows produces a post-mortem dump,
# and configure WER LocalDumps to capture the dump to a known directory so we
# can collect it as a Buildkite artifact.
$env:GOTRACEBACK = "crash"

$dumpDir = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH "build\crashdumps"
New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
$werKey = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
try {
    if (-not (Test-Path $werKey)) { New-Item -Path $werKey -Force | Out-Null }
    Set-ItemProperty -Path $werKey -Name "DumpFolder" -Value $dumpDir -Type ExpandString
    Set-ItemProperty -Path $werKey -Name "DumpType"   -Value 2 -Type DWord    # 2 = full
    Set-ItemProperty -Path $werKey -Name "DumpCount"  -Value 10 -Type DWord
    Write-Host "WER LocalDumps configured: DumpFolder=$dumpDir DumpType=2 DumpCount=10"
} catch {
    Write-Warning "Failed to configure WER LocalDumps: $_ (continuing; dumps may go to default path)"
}
# === END debug/13796 instrumentation ===

Write-Host "--- Build"
mage build

if ($LASTEXITCODE -ne 0) {
  exit 1
}

Write-Host "--- Unit tests"
$env:TEST_COVERAGE = $true
$env:RACE_DETECTOR = $true
$unitTestExit = 1
try {
    mage unitTest
    $unitTestExit = $LASTEXITCODE

    # Best-effort: when mage panics, the .cov/.xml files may not exist. Use
    # SilentlyContinue so a missing source doesn't throw and abort the script
    # before dump collection runs in the finally block below.
    Write-Host "--- Prepare artifacts"
    $buildkiteJobId = $env:BUILDKITE_JOB_ID
    Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out" -EA SilentlyContinue
    Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml" -EA SilentlyContinue
} finally {
    # === BEGIN debug/13796 dump collection (runs even on panic/error) ===
    # Sweep any minidumps written to the default WER location too, in case the
    # registry write didn't take effect, and stash test binaries alongside so
    # dumps can be symbolicated offline.
    $defaultDumps = Join-Path $env:LOCALAPPDATA "CrashDumps"
    if (Test-Path $defaultDumps) {
        Get-ChildItem -Path $defaultDumps -Filter '*.dmp' -EA 0 | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $dumpDir -Force -EA SilentlyContinue
        }
    }
    $dumpFiles = Get-ChildItem -Path $dumpDir -Filter '*.dmp' -EA 0
    if ($dumpFiles) {
        Write-Host "--- Captured $($dumpFiles.Count) crash dump(s) for #13796 analysis"
        $dumpFiles | ForEach-Object { Write-Host ("    " + $_.FullName + " (" + $_.Length + " bytes)") }
        Get-ChildItem -Path . -Recurse -Filter '*.test.exe' -EA 0 | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $dumpDir -Force -EA SilentlyContinue
        }
    } else {
        Write-Host "--- No crash dumps captured (no panic this run)"
    }
    # === END debug/13796 dump collection ===
}

if ($unitTestExit -ne 0) {
  exit $unitTestExit
}



# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))

# Boot-time noise probe; self-gates on uptime, runs detached so it can't block the job.
$probe = Join-Path $env:BUILDKITE_BUILD_CHECKOUT_PATH '.buildkite\scripts\boot-probe.ps1'
if (Test-Path $probe) {
    Start-Process powershell `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $probe `
        -WindowStyle Hidden
}

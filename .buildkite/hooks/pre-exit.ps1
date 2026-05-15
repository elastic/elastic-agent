# Collect boot-probe artifacts if the probe ran.

$ErrorActionPreference = 'SilentlyContinue'

$Out = 'C:\boot-probe'
if (-not (Test-Path $Out)) { return }

if (Test-Path "$Out\sampler.jobid") {
    $id = Get-Content "$Out\sampler.jobid" | Select-Object -First 1
    if ($id) {
        Get-Job -Id $id | Stop-Job
        Get-Job -Id $id | Remove-Job
    }
}

$zip = 'boot-probe.zip'
Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip -Force
if (Test-Path $zip) {
    & buildkite-agent artifact upload $zip
}

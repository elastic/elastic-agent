# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))

# Begin DRA override
# When DRA is not creating the binaries, we can use the files
# to override
if (Test-Path -Path .beat-version) {
    $beat_version = Get-Content -Path .agent-version -Raw
    $env:BEAT_VERSION = $beat_version.Trim()
}

if (Test-Path -Path .agent-version) {
    $agent_version = Get-Content -Path .agent-version -Raw
    $agent_version = $agent_version.Trim()
    $env:AGENT_PACKAGE_VERSION = $agent_version
    $env:AGENT_VERSION = "$agent_version-SNAPSHOT"
}
# End DRA override

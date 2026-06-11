# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))
# awscli, jq, and zstandard are pre-installed on Windows VM images.
# Pin GOMODCACHE to a stable path that matches the S3 cache plugin config.
$env:GOMODCACHE = "$env:USERPROFILE\go\pkg\mod"
New-Item -ItemType Directory -Force -Path $env:GOMODCACHE | Out-Null

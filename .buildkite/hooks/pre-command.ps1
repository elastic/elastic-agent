# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))
choco install awscli jq zstandard -y
Write-Output "Env Path Before: $env:Path"
$env:Path += ";C:\Program Files\Amazon\AWSCLIV2\"
Write-Output "Env Path After: $env:Path"
Write-Output "AWS CLI installed. Version:"
aws --version

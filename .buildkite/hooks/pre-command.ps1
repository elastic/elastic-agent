# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))
choco install awscli jq -y
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Write-Output "AWS CLI installed. Version:"
aws --version

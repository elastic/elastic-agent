# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))

if ($env:BUILDKITE_GROUP_KEY -like "*integration-tests*") {
  . "$PWD\.buildkite/scripts/set-bk-analytics-token.ps1"  
}
$ErrorActionPreference = "Stop"

. "$PWD\.buildkite\scripts\retry.ps1"

Write-Host "~~~ Set BUILDKITE_ANALYTICS_TOKEN :vault:"
$BUILDKITE_ANALYTICS_TOKEN = Retry-Command -ScriptBlock {
  vault kv get -field=token kv/ci-shared/platform-ingest/buildkite_analytics_token
}
# [System.Environment]::SetEnvironmentVariable("BUILDKITE_ANALYTICS_TOKEN", $BUILDKITE_ANALYTICS_TOKEN, [System.EnvironmentVariableTarget]::User)
$env.BUILDKITE_ANALYTICS_TOKEN = $BUILDKITE_ANALYTICS_TOKEN

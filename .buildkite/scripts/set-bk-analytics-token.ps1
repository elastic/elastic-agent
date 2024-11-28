Write-Host "--- Prepare BK test analytics token :vault:"
$BUILDKITE_ANALYTICS_TOKEN = & vault kv get -field=token kv/ci-shared/platform-ingest/buildkite_analytics_token
[System.Environment]::SetEnvironmentVariable("BUILDKITE_ANALYTICS_TOKEN", $BUILDKITE_ANALYTICS_TOKEN, [System.EnvironmentVariableTarget]::Machine)

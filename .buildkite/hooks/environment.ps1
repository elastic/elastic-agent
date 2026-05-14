# Required: Upload destination
$env:BUILDKITE_ARTIFACT_UPLOAD_DESTINATION="gs://buildkite-elastic-agent/$env:BUILDKITE_PIPELINE_ID/$env:BUILDKITE_BUILD_ID/$env:BUILDKITE_JOB_ID"

# Optional: ACL
$env:BUILDKITE_GS_ACL="private"

# Optional: Authenticated access in UI
$env:BUILDKITE_GCS_ACCESS_HOST="storage.cloud.google.com"

# Optional: Debug
$env:BUILDKITE_AGENT_LOG_LEVEL="debug"
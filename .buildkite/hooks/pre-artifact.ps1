# Required: Upload destination
$env:BUILDKITE_ARTIFACT_UPLOAD_DESTINATION="gs://buildkite-elastic-agent/$env:BUILDKITE_PIPELINE_ID/$env:BUILDKITE_BUILD_ID/$env:BUILDKITE_JOB_ID"

# Disable ACL setting for GCS buckets with uniform bucket-level access
$env:BUILDKITE_GS_ACL=""

# Optional: Authenticated access in UI
$env:BUILDKITE_GCS_ACCESS_HOST="storage.cloud.google.com"

# Optional: Experimental https://buildkite.com/docs/agent/self-hosted/configure/experiments#available-experiments-normalised-upload-paths
$env:BUILDKITE_AGENT_EXPERIMENT="normalised-upload-paths"

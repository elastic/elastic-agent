# !/bin/bash
echo "--- Set BUILDKITE_ANALYTICS_TOKEN :vault:"
BUILDKITE_ANALYTICS_TOKEN=$(retry 5 vault kv get -field token kv/ci-shared/platform-ingest/buildkite_analytics_token)
export BUILDKITE_ANALYTICS_TOKEN
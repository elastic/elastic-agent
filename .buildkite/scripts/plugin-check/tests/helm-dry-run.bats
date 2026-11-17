#!/usr/bin/env bats
# helm-charts.sh must not upload to GCS or trigger the publish pipeline when DRY_RUN=true.

SCRIPT="${BATS_TEST_DIRNAME}/../../steps/helm-charts.sh"

setup() {
  W="$(mktemp -d)"
  mkdir -p "$W/bin" "$W/.buildkite/scripts/steps"
  : > "$W/.buildkite/scripts/common.sh"
  cp "${BATS_TEST_DIRNAME}/../../steps/trigger-publish-helm-charts.sh" "$W/.buildkite/scripts/steps/"
  for c in mage gcloud buildkite-agent; do
    cat > "$W/bin/$c" <<STUB
#!/usr/bin/env bash
echo "$c \$*" >> "$W/calls"
[[ "$c" == mage ]] && touch elastic-agent-1.0.0.tgz
[[ "$c" == buildkite-agent ]] && cat > /dev/null
exit 0
STUB
    chmod +x "$W/bin/$c"
  done
  export PATH="$W/bin:$PATH"
  cd "$W"
}

teardown() { rm -rf "$W"; }

@test "DRY_RUN=true packages the chart but neither uploads nor triggers publish" {
  SNAPSHOT=true HELM_REPO_ENV=dev DRY_RUN=true run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  grep -q "mage helm:package" calls
  ! grep -q gcloud calls
  ! grep -q buildkite-agent calls
}

@test "without DRY_RUN it still uploads and triggers publish" {
  SNAPSHOT=true HELM_REPO_ENV=dev run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  grep -q "gcloud storage cp" calls
  grep -q "buildkite-agent pipeline upload" calls
}

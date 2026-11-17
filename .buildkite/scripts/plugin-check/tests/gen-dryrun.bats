#!/usr/bin/env bats

GEN="${BATS_TEST_DIRNAME}/../gen-dryrun.sh"

export BUILDKITE_PULL_REQUEST=123 BUILDKITE_COMMIT=abc BUILDKITE_BRANCH=feat

@test "bumping a pin in the binary-dra pipeline triggers one dry-run build" {
  run "$GEN" <<<$'elastic/oblt-google-auth\tv1.3.5\t.buildkite/pipeline.elastic-agent-binary-dra.yml\nelastic/vault-docker-login\tv0.8.1\t.buildkite/pipeline.elastic-agent-binary-dra.yml'
  [ "$status" -eq 0 ]
  [[ "$output" == "steps:"* ]]
  [ "$(grep -c 'trigger:' <<<"$output")" -eq 1 ]
  [[ "$output" == *'trigger: "elastic-agent-binary-dra"'* ]]
  [[ "$output" == *'DRY_RUN: "true"'* ]]
  [[ "$output" == *'RUN_SNAPSHOT: "true"'* ]]
  [[ "$output" == *'ELASTIC_SLACK_NOTIFICATIONS_ENABLED: "false"'* ]]
  [[ "$output" == *'commit: "abc"'* ]]
}

@test "pipelines already triggered by the main PR build get no duplicate" {
  run "$GEN" <<<$'elastic/vault-docker-login\tv0.8.1\t.buildkite/pipeline.elastic-agent-package.yml'
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "helm-charts pipeline gets DRY_RUN env" {
  run "$GEN" <<<$'elastic/oblt-google-auth\tv1.3.5\t.buildkite/pipeline.elastic-agent-helm-charts.yml'
  [ "$status" -eq 0 ]
  [[ "$output" == *'trigger: "elastic-agent-helm-charts"'* ]]
  [[ "$output" == *'DRY_RUN: "true"'* ]]
}

@test "files not in the coverage map and empty input print nothing" {
  run "$GEN" <<<$'sparse-checkout\tv1.11.0\t.buildkite/scripts/upload_dra_staging.sh'
  [ -z "$output" ]
  run "$GEN" <<<""
  [ -z "$output" ]
}

@test "every dry-run trigger sets a dry-run switch" {
  while IFS=$'\t' read -r _f _s covered env; do
    [[ "$_f" == \#* || "$covered" == true ]] && continue
    [[ "$env" == *DRY_RUN=true* ]]
  done < "${BATS_TEST_DIRNAME}/../coverage.tsv"
}

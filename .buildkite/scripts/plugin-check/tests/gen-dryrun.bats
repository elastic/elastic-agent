#!/usr/bin/env bats

GEN="${BATS_TEST_DIRNAME}/../gen-dryrun.sh"

export BUILDKITE_PULL_REQUEST=123 BUILDKITE_COMMIT=abc BUILDKITE_BRANCH=feat

@test "binary-dra is deliberately not dry-run (cost, slack notify, no plugin gain)" {
  run "$GEN" <<<$'elastic/oblt-google-auth\tv1.3.5\t.buildkite/pipeline.elastic-agent-binary-dra.yml'
  [ "$status" -eq 0 ]
  [ -z "$output" ]
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

@test "agentless-app-release is covered by main only for PRs against main" {
  export BUILDKITE_PULL_REQUEST_BASE_BRANCH=main
  run "$GEN" <<<$'elastic/vault-docker-login\tv0.8.1\t.buildkite/pipeline.agentless-app-release.yaml'
  [ -z "$output" ]
  export BUILDKITE_PULL_REQUEST_BASE_BRANCH=9.4
  run "$GEN" <<<$'elastic/vault-docker-login\tv0.8.1\t.buildkite/pipeline.agentless-app-release.yaml'
  [[ "$output" == *'trigger: "agentless-serverless-release"'* ]]
  [[ "$output" == *'DRY_RUN: "true"'* ]]
}

@test "branch names cannot break the YAML or be re-interpolated by the agent" {
  export BUILDKITE_BRANCH='a$b"c\d' BUILDKITE_PULL_REQUEST_BASE_BRANCH=main
  run "$GEN" <<<$'elastic/oblt-google-auth\tv1.3.5\t.buildkite/pipeline.elastic-agent-helm-charts.yml'
  [ "$status" -eq 0 ]
  [[ "$output" == *'branch: "a$$b\"c\\d"'* ]]
  echo "$output" | python3 -c 'import sys,yaml; d=yaml.safe_load(sys.stdin); assert d["steps"][0]["build"]["branch"]=="a$$b\"c\\d"'
}

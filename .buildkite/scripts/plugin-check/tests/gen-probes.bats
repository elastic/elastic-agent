#!/usr/bin/env bats

bats_require_minimum_version 1.5.0

GEN="${BATS_TEST_DIRNAME}/../gen-probes.sh"

@test "no pins prints nothing" {
  run "$GEN" <<<""
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "vault-docker-login probe loads the new pinned version" {
  run "$GEN" <<<$'elastic/vault-docker-login\tv0.8.1\tf.yml'
  [ "$status" -eq 0 ]
  [[ "$output" == "steps:"* ]]
  [[ "$output" == *"- elastic/vault-docker-login#v0.8.1:"* ]]
  [[ "$output" == *'key: "probe-elastic-vault-docker-login-v0-8-1-r0"'* ]]
  [[ "$output" == *"docker logout docker.elastic.co"* ]]
}

@test "plugin without an explicit probe gets no step (static check only)" {
  run --separate-stderr "$GEN" <<<$'some-org/new-thing\tv1.2.3\tf.yml'
  [ "$status" -eq 0 ]
  [ -z "$output" ]
  [[ "$stderr" == *"no probe for some-org/new-thing"* ]]
}

@test "duplicate plugin+version across files yields one probe" {
  run "$GEN" <<<$'sparse-checkout\tv1.11.0\ta.yml\nsparse-checkout\tv1.11.0\tb.yml'
  [ "$status" -eq 0 ]
  [ "$(grep -c 'key: "probe-' <<<"$output")" -eq 1 ]
}

@test "no unreplaced placeholders and secrets are never echoed" {
  run "$GEN" <<<$'elastic/vault-secrets\tv0.1.1\ta.yml\nelastic/vault-github-token\tv0.2.3\ta.yml\nelastic/oblt-cli\tv0.4.5\ta.yml'
  [ "$status" -eq 0 ]
  [[ "$output" != *__* ]]
  [[ "$output" != *"echo \$"* ]]
}

@test "probe keys change with the retry count so a retried step can re-upload" {
  BUILDKITE_RETRY_COUNT=2 run "$GEN" <<<$'sparse-checkout\tv1.11.0\tf.yml'
  [[ "$output" == *'key: "probe-sparse-checkout-v1-11-0-r2"'* ]]
}

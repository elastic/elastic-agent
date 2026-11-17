#!/usr/bin/env bats

PINS="${BATS_TEST_DIRNAME}/../pins.sh"

setup() {
  REPO="$(mktemp -d)"
  cd "$REPO"
  git init -q -b main
  git config user.email t@t
  git config user.name t
  mkdir -p .buildkite/scripts
  cat > .buildkite/pipeline.yml <<'Y'
steps:
  - plugins:
      - elastic/vault-docker-login#v0.5.2:
          x: y
      - sparse-checkout#v1.6.0:
          paths: [a]
      - elastic/gcp-secret-manager#v1.3.0-elastic:
          z: 1
      - avaly/gcp-secret-manager#v1.2.0:
          z: 1
Y
  cat > .buildkite/scripts/up.sh <<'S'
cat <<E
      - elastic/oblt-google-auth#v1.3.5:
E
S
  git add -A && git commit -q -m base
}

teardown() { rm -rf "$REPO"; }

@test "list finds yml and sh pins, skips fork-tag plugins" {
  run "$PINS" list
  [ "$status" -eq 0 ]
  [[ "$output" == *$'elastic/vault-docker-login\tv0.5.2\t.buildkite/pipeline.yml'* ]]
  [[ "$output" == *$'sparse-checkout\tv1.6.0\t.buildkite/pipeline.yml'* ]]
  [[ "$output" == *$'elastic/oblt-google-auth\tv1.3.5\t.buildkite/scripts/up.sh'* ]]
  [[ "$output" != *gcp-secret-manager* ]]
}

@test "list --files restricts to given files" {
  run "$PINS" list --files .buildkite/scripts/up.sh
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | wc -l)" -eq 1 ]
}

@test "changed returns only the bumped pin" {
  git checkout -q -b pr
  sed -i 's/vault-docker-login#v0.5.2/vault-docker-login#v0.8.1/' .buildkite/pipeline.yml
  git commit -qam bump
  run "$PINS" changed main
  [ "$status" -eq 0 ]
  [ "$output" = $'elastic/vault-docker-login\tv0.8.1\t.buildkite/pipeline.yml' ]
}

@test "changed with no pin change prints nothing" {
  git checkout -q -b pr
  echo "# c" >> .buildkite/pipeline.yml
  git commit -qam nochange
  run "$PINS" changed main
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "changed handles a removed pin" {
  git checkout -q -b pr
  sed -i '/sparse-checkout/,+1d' .buildkite/pipeline.yml
  git commit -qam rm
  run "$PINS" changed main
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "changed exits 2 when base ref is unresolvable" {
  run "$PINS" changed origin/does-not-exist
  [ "$status" -eq 2 ]
}

@test "suffixed tags keep the whole version" {
  printf -- '      - elastic/foo#v1.2.3-rc1:\n' > .buildkite/x.yml
  run "$PINS" list --files .buildkite/x.yml
  [ "$output" = $'elastic/foo\tv1.2.3-rc1\t.buildkite/x.yml' ]
}

@test "floating refs used as plugin keys are reported, issue refs and URLs are not" {
  printf -- '      - elastic/foo#main:\n      - elastic/bar#0a1b2c3d4e5f:\n# see elastic/elastic-agent#18037 and https://github.com/x/y#v1.2.3\nx: "${1#v}"\n' > .buildkite/x.yml
  run "$PINS" list --files .buildkite/x.yml
  [[ "$output" == *$'elastic/foo\tmain\t'* ]]
  [[ "$output" == *$'elastic/bar\t0a1b2c3d4e5f\t'* ]]
  [ "$(wc -l <<<"$output")" -eq 2 ]
}

@test "catalog-info.yaml pins are scanned and diffed" {
  printf -- 'initial_step_plugins:\n  - sparse-checkout#v1.6.0:\n' > catalog-info.yaml
  git add -A && git commit -qm cat
  git checkout -q -b pr2
  sed -i 's/v1.6.0/v1.11.0/' catalog-info.yaml && git commit -qam bump
  run "$PINS" list
  [[ "$output" == *$'sparse-checkout\tv1.6.0\tcatalog-info.yaml'* || "$output" == *$'sparse-checkout\tv1.11.0\tcatalog-info.yaml'* ]]
  run "$PINS" changed main
  [[ "$output" == *$'sparse-checkout\tv1.11.0\tcatalog-info.yaml'* ]]
}

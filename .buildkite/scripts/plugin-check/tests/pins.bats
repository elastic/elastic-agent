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

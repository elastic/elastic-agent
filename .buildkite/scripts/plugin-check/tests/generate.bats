#!/usr/bin/env bats

bats_require_minimum_version 1.5.0

GEN="${BATS_TEST_DIRNAME}/../generate.sh"

setup() {
  export GH_STUB_DIR="$(mktemp -d)"
  mkdir -p "$GH_STUB_DIR/bin"
  cat > "$GH_STUB_DIR/bin/gh" <<'S'
#!/usr/bin/env bash
path="$2"
case "$path" in
  */git/ref/tags/*) [[ "$path" != *v9.9.9* ]] || exit 1; echo '{}' ;;
  */releases/tags/*) [[ "$path" == *v0.9.0* ]] && echo true || echo false ;;
esac
S
  chmod +x "$GH_STUB_DIR/bin/gh"
  export PATH="$GH_STUB_DIR/bin:$PATH"

  REPO="$(mktemp -d)"
  cd "$REPO"
  git init -q -b main
  git config user.email t@t
  git config user.name t
  mkdir -p .buildkite
  printf -- '- elastic/vault-docker-login#v0.5.2:\n' > .buildkite/pipeline.elastic-agent-binary-dra.yml
  git add -A && git commit -q -m base
  git checkout -q -b pr
  export BUILDKITE_PULL_REQUEST=7 BUILDKITE_COMMIT=abc BUILDKITE_BRANCH=pr
}

teardown() { rm -rf "$REPO" "$GH_STUB_DIR"; }

bump() {
  sed -i "s/vault-docker-login#v[0-9.]*/vault-docker-login#$1/" .buildkite/pipeline.elastic-agent-binary-dra.yml
  git commit -qam bump
}

@test "bumped pin yields a probe and a dry-run trigger in one pipeline" {
  bump v0.8.1
  run --separate-stderr "$GEN" main
  [ "$status" -eq 0 ]
  [ "$(grep -c '^steps:' <<<"$output")" -eq 1 ]
  [[ "$output" == *"probe vault-docker-login v0.8.1"* ]]
  [[ "$output" == *'trigger: "elastic-agent-binary-dra"'* ]]
  [[ "$output" != *"ok elastic/"* ]]   # verification chatter must not pollute the pipeline
}

@test "no pin change prints nothing and succeeds" {
  echo "# c" >> .buildkite/pipeline.elastic-agent-binary-dra.yml; git commit -qam c
  run --separate-stderr "$GEN" main
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "draft release fails the check" {
  bump v0.9.0
  run --separate-stderr "$GEN" main
  [ "$status" -eq 1 ]
  [[ "$stderr" == *"draft"* ]]
}

@test "unresolvable base fails loudly instead of reporting no changes" {
  run --separate-stderr "$GEN" origin/nope
  [ "$status" -eq 2 ]
}

#!/usr/bin/env bats

VERIFY="${BATS_TEST_DIRNAME}/../verify-tags.sh"

setup() {
  export GH_STUB_DIR="$(mktemp -d)"
  mkdir -p "$GH_STUB_DIR/bin"
  cat > "$GH_STUB_DIR/bin/gh" <<'S'
#!/usr/bin/env bash
# args: api repos/<org>/<repo>/(releases/tags|git/ref/tags)/<tag> [--jq .draft]
echo "$*" >> "$GH_STUB_DIR/calls"
path="$2"
key="$(echo "$path" | sed -E 's#repos/([^/]+)/([^/]+)/(releases/tags|git/ref/tags)/(.*)#\3-\1-\2-\4#; s#/#_#g')"
case "$path" in
  */releases/tags/*)
    [[ -e "$GH_STUB_DIR/$key" ]] || exit 1
    cat "$GH_STUB_DIR/$key" ;;
  */git/ref/tags/*)
    [[ -e "$GH_STUB_DIR/$key" ]] || exit 1
    echo '{}' ;;
esac
S
  chmod +x "$GH_STUB_DIR/bin/gh"
  export PATH="$GH_STUB_DIR/bin:$PATH"
}

teardown() { rm -rf "$GH_STUB_DIR"; }

tag()     { echo '{}' > "$GH_STUB_DIR/git_ref_tags-$1-$2-$3"; }
release() { echo "$4" > "$GH_STUB_DIR/releases_tags-$1-$2-$3"; }

@test "published release with tag passes" {
  tag elastic vault-docker-login-buildkite-plugin v0.8.1
  release elastic vault-docker-login-buildkite-plugin v0.8.1 false
  run "$VERIFY" <<<$'elastic/vault-docker-login\tv0.8.1\tf.yml'
  [ "$status" -eq 0 ]
}

@test "tag-only plugin (no GitHub release) passes" {
  tag buildkite-plugins sparse-checkout-buildkite-plugin v1.11.0
  run "$VERIFY" <<<$'sparse-checkout\tv1.11.0\tf.yml'
  [ "$status" -eq 0 ]
}

@test "draft release fails" {
  tag elastic vault-docker-login-buildkite-plugin v0.9.0
  release elastic vault-docker-login-buildkite-plugin v0.9.0 true
  run "$VERIFY" <<<$'elastic/vault-docker-login\tv0.9.0\tf.yml'
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL elastic/vault-docker-login#v0.9.0"*draft* ]]
}

@test "missing tag fails" {
  run "$VERIFY" <<<$'elastic/vault-docker-login\tv9.9.9\tf.yml'
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL elastic/vault-docker-login#v9.9.9"*tag* ]]
}

@test "same plugin and version in several files is checked once" {
  tag elastic vault-docker-login-buildkite-plugin v0.8.1
  run "$VERIFY" <<<$'elastic/vault-docker-login\tv0.8.1\ta.yml\nelastic/vault-docker-login\tv0.8.1\tb.yml'
  [ "$status" -eq 0 ]
  [ "$(grep -c 'git/ref/tags' "$GH_STUB_DIR/calls")" -eq 1 ]
}

@test "empty input passes" {
  run "$VERIFY" <<<""
  [ "$status" -eq 0 ]
}

#!/usr/bin/env bats

bats_require_minimum_version 1.5.0

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
if [[ -e "$GH_STUB_DIR/err-$key" ]]; then cat "$GH_STUB_DIR/err-$key" >&2; exit 1; fi
case "$path" in
  */releases/latest)
    f="$GH_STUB_DIR/latest-$(echo "$path" | sed -E 's#repos/([^/]+)/([^/]+)/.*#\1-\2#')"
    [[ -e "$f" ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    cat "$f" ;;
  */releases/tags/*)
    [[ -e "$GH_STUB_DIR/$key" ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    cat "$GH_STUB_DIR/$key" ;;
  */git/ref/tags/*)
    [[ -e "$GH_STUB_DIR/$key" ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
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

@test "floating ref (branch or sha) fails" {
  run "$VERIFY" <<<$'elastic/foo\tmain\tf.yml'
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL elastic/foo#main"*floating* ]]
}

@test "suffixed tag is verified as a whole" {
  tag elastic foo-buildkite-plugin v1.2.3-rc1
  run "$VERIFY" <<<$'elastic/foo\tv1.2.3-rc1\tf.yml'
  [ "$status" -eq 0 ]
  run "$VERIFY" <<<$'elastic/foo\tv1.2.3\tf.yml'
  [ "$status" -eq 1 ]
}

@test "gh error on the tag lookup is a verification error, not 'tag not found'" {
  echo "gh: API rate limit exceeded (HTTP 403)" > "$GH_STUB_DIR/err-git_ref_tags-elastic-foo-buildkite-plugin-v1.0.0"
  run "$VERIFY" <<<$'elastic/foo\tv1.0.0\tf.yml'
  [ "$status" -eq 1 ]
  [[ "$output" == *"ERROR elastic/foo#v1.0.0"*"HTTP 403"* ]]
  [[ "$output" != *"not found"* ]]
}

@test "gh error on the release lookup does not let a pin through" {
  tag elastic foo-buildkite-plugin v1.0.0
  echo "gh: Server Error (HTTP 502)" > "$GH_STUB_DIR/err-releases_tags-elastic-foo-buildkite-plugin-v1.0.0"
  run "$VERIFY" <<<$'elastic/foo\tv1.0.0\tf.yml'
  [ "$status" -eq 1 ]
  [[ "$output" == *"ERROR elastic/foo#v1.0.0"* ]]
}

@test "missing gh is reported clearly" {
  run env PATH=/nonexistent /bin/bash "$VERIFY" <<<$'elastic/foo\tv1.0.0\tf.yml'
  [ "$status" -eq 3 ]
  [[ "$output" == *"gh"*"not found"* ]]
}

@test "pin older than the latest release warns but passes" {
  tag elastic foo-buildkite-plugin v1.0.0
  release elastic foo-buildkite-plugin v1.0.0 false
  echo "v1.1.0" > "$GH_STUB_DIR/latest-elastic-foo-buildkite-plugin"
  run "$VERIFY" <<<$'elastic/foo\tv1.0.0\tf.yml'
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARN outdated elastic/foo: v1.0.0 (latest v1.1.0)"* ]]
}

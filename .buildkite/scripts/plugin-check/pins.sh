#!/usr/bin/env bash
# Parse Buildkite plugin pins (org/name#ref) from .buildkite files and catalog-info.yaml.
#
#   pins.sh list [--files F...]   all pins, as: plugin<TAB>version<TAB>file
#   pins.sh changed <base-ref>    pins added/changed in `git diff <base-ref>...HEAD`
#
# A pin is a semver tag (vX.Y[.Z][-suffix]) anywhere, or any other non-numeric ref
# (branch, sha) when used as a YAML key (`name#ref:`), so floating pins get reported
# (verify-tags.sh fails on them). Issue refs (`org/repo#123`) and URLs are ignored.
# Exit 2 if <base-ref> cannot be resolved or has no merge base (e.g. shallow clone).
set -euo pipefail

# Token must start at a word boundary; org part has no dots so URLs (github.com/x/y#v1) never match.
TOKEN_RE='(^|[[:space:]"'"'"'])[A-Za-z0-9_-]+(/[A-Za-z0-9_.-]+)?#[A-Za-z0-9][A-Za-z0-9._+-]*:?'
SEMVER_RE='^v[0-9]+(\.[0-9]+){1,2}(-[A-Za-z0-9.+-]+)?$'
# Fork tags that are not comparable as semver.
SKIP_RE='^(elastic|avaly)/gcp-secret-manager$'
EXCLUDE_DIR='.buildkite/scripts/plugin-check/'
SCOPE=(.buildkite catalog-info.yaml)

# stdin: "<file>:<token>" lines -> "plugin<TAB>version<TAB>file"
normalize() {
  local line file token plugin ref keyed
  while IFS= read -r line; do
    file="${line%%:*}"
    token="${line#*:}"
    token="${token#"${token%%[![:space:]\"\']*}"}"
    keyed=0
    if [[ "$token" == *: ]]; then keyed=1; token="${token%:}"; fi
    plugin="${token%%#*}"
    ref="${token#*#}"
    [[ "$plugin" =~ $SKIP_RE ]] && continue
    if [[ ! "$ref" =~ $SEMVER_RE ]]; then
      # floating ref: only when used as a plugin key and not a plain number (issue ref)
      [[ $keyed -eq 1 && ! "$ref" =~ ^[0-9]+$ ]] || continue
    fi
    printf '%s\t%s\t%s\n' "$plugin" "$ref" "$file"
  done | sort -u
}

cmd_list() {
  local files=()
  if [[ "${1:-}" == "--files" ]]; then
    shift
    files=("$@")
  else
    while IFS= read -r f; do files+=("$f"); done < <(
      git ls-files '.buildkite/*.yml' '.buildkite/*.yaml' '.buildkite/*.sh' \
        '.buildkite/**/*.yml' '.buildkite/**/*.yaml' '.buildkite/**/*.sh' catalog-info.yaml |
        grep -v "^${EXCLUDE_DIR}" | sort -u)
  fi
  [[ ${#files[@]} -gt 0 ]] || return 0
  grep -HoE "$TOKEN_RE" "${files[@]}" 2>/dev/null | normalize || true
}

cmd_changed() {
  local base="${1:?base ref required}"
  if ! git rev-parse --verify -q "${base}^{commit}" >/dev/null; then
    echo "pins.sh: cannot resolve base ref '${base}'" >&2
    exit 2
  fi
  local diff
  if ! diff="$(git diff -U0 "${base}...HEAD" -- "${SCOPE[@]}" 2>&1)"; then
    echo "pins.sh: git diff failed (shallow clone?): ${diff}" >&2
    exit 2
  fi
  local file="" line tok
  while IFS= read -r line; do
    case "$line" in
      "+++ b/"*) file="${line#+++ b/}" ;;
      "+++"*) ;;
      "+"*)
        [[ "$file" == "$EXCLUDE_DIR"* ]] && continue
        while IFS= read -r tok; do
          printf '%s:%s\n' "$file" "$tok"
        done < <(grep -oE "$TOKEN_RE" <<<"$line" || true)
        ;;
    esac
  done <<<"$diff" | normalize || true
}

case "${1:-}" in
  list) shift; cmd_list "$@" ;;
  changed) shift; cmd_changed "$@" ;;
  *) echo "usage: pins.sh list [--files F...] | changed <base-ref>" >&2; exit 64 ;;
esac

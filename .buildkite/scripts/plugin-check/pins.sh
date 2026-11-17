#!/usr/bin/env bash
# Parse Buildkite plugin pins (org/name#vX.Y.Z) from .buildkite files.
#
#   pins.sh list [--files F...]   all pins, as: plugin<TAB>version<TAB>file
#   pins.sh changed <base-ref>    pins added/changed in `git diff <base-ref>...HEAD`
#
# Exit 2 if <base-ref> cannot be resolved or has no merge base (e.g. shallow clone).
set -euo pipefail

PIN_RE='[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?#v[0-9]+(\.[0-9]+){1,2}'
# Fork tags that are not comparable as semver.
SKIP_RE='^(elastic|avaly)/gcp-secret-manager$'
EXCLUDE_DIR='.buildkite/scripts/plugin-check/'

# stdin: "<file>:<pin>" lines -> "plugin<TAB>version<TAB>file", skip-listed removed.
normalize() {
  awk -F'[:#]' -v skip="$SKIP_RE" '
    { file=$1; plugin=$2; ver=$3; sub(/^.*:/, "", plugin)
      if (plugin ~ skip) next
      printf "%s\t%s\t%s\n", plugin, ver, file }' | sort -u
}

cmd_list() {
  local files=()
  if [[ "${1:-}" == "--files" ]]; then
    shift
    files=("$@")
  else
    while IFS= read -r f; do files+=("$f"); done < <(
      git ls-files '.buildkite/*.yml' '.buildkite/*.yaml' '.buildkite/*.sh' \
        '.buildkite/**/*.yml' '.buildkite/**/*.yaml' '.buildkite/**/*.sh' |
        grep -v "^${EXCLUDE_DIR}" | sort -u)
  fi
  [[ ${#files[@]} -gt 0 ]] || return 0
  grep -HoE "$PIN_RE" "${files[@]}" 2>/dev/null | normalize || true
}

cmd_changed() {
  local base="${1:?base ref required}"
  if ! git rev-parse --verify -q "${base}^{commit}" >/dev/null; then
    echo "pins.sh: cannot resolve base ref '${base}'" >&2
    exit 2
  fi
  local diff
  if ! diff="$(git diff -U0 "${base}...HEAD" -- .buildkite 2>&1)"; then
    echo "pins.sh: git diff failed (shallow clone?): ${diff}" >&2
    exit 2
  fi
  local file="" line pin
  while IFS= read -r line; do
    case "$line" in
      "+++ b/"*) file="${line#+++ b/}" ;;
      "+++"*) ;;
      "+"*)
        [[ "$file" == "$EXCLUDE_DIR"* ]] && continue
        while IFS= read -r pin; do
          printf '%s:%s\n' "$file" "$pin"
        done < <(grep -oE "$PIN_RE" <<<"$line" || true)
        ;;
    esac
  done <<<"$diff" | normalize || true
}

case "${1:-}" in
  list) shift; cmd_list "$@" ;;
  changed) shift; cmd_changed "$@" ;;
  *) echo "usage: pins.sh list [--files F...] | changed <base-ref>" >&2; exit 64 ;;
esac

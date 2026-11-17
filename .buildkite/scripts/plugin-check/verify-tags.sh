#!/usr/bin/env bash
# Verify plugin pins resolve to existing, non-draft tags.
# stdin: plugin<TAB>version<TAB>file (output of pins.sh). Exit 1 on any FAIL.
# Unqualified plugin `name` -> buildkite-plugins/<name>-buildkite-plugin;
# `org/name` -> <org>/<name>-buildkite-plugin.
set -uo pipefail

repo_for() {
  local plugin="$1"
  if [[ "$plugin" == */* ]]; then
    echo "${plugin%%/*}/${plugin#*/}-buildkite-plugin"
  else
    echo "buildkite-plugins/${plugin}-buildkite-plugin"
  fi
}

declare -A seen versions
rc=0
while IFS=$'\t' read -r plugin version _file; do
  [[ -n "${plugin:-}" ]] || continue
  key="${plugin}#${version}"
  [[ -z "${seen[$key]:-}" ]] || continue
  seen[$key]=1
  case " ${versions[$plugin]:-} " in *" $version "*) ;; *) versions[$plugin]+="${versions[$plugin]:+ }$version" ;; esac

  repo="$(repo_for "$plugin")"
  if ! gh api "repos/${repo}/git/ref/tags/${version}" >/dev/null 2>&1; then
    echo "FAIL ${key}: tag ${version} not found in ${repo}"
    rc=1
    continue
  fi
  # A release may not exist (tag-only plugins); if it does, it must not be a draft.
  if draft="$(gh api "repos/${repo}/releases/tags/${version}" --jq .draft 2>/dev/null)" && [[ "$draft" == "true" ]]; then
    echo "FAIL ${key}: release is a draft"
    rc=1
    continue
  fi
  echo "ok ${key}"
done

for plugin in "${!versions[@]}"; do
  [[ "${versions[$plugin]}" == *" "* ]] && echo "WARN drift ${plugin}: ${versions[$plugin]}"
done
exit "$rc"

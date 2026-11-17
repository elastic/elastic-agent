#!/usr/bin/env bash
# Verify plugin pins resolve to existing, non-draft semver tags.
# stdin: plugin<TAB>version<TAB>file (output of pins.sh).
# Exit: 0 ok / 1 any FAIL or ERROR / 3 gh not installed.
#   FAIL  = the pin is wrong (floating ref, tag missing, draft release)
#   ERROR = we could not tell (gh/API error other than 404) - never treated as a pass
#   WARN  = non-failing (version drift across files, pin older than the latest release)
# Unqualified plugin `name` -> buildkite-plugins/<name>-buildkite-plugin;
# `org/name` -> <org>/<name>-buildkite-plugin.
set -uo pipefail

SEMVER_RE='^v[0-9]+(\.[0-9]+){1,2}(-[A-Za-z0-9.+-]+)?$'

if ! command -v gh >/dev/null 2>&1; then
  echo "verify-tags: gh not found on PATH" >&2
  echo "gh CLI not found" # visible in the build log even if stderr is dropped
  exit 3
fi

repo_for() {
  local plugin="$1"
  if [[ "$plugin" == */* ]]; then
    echo "${plugin%%/*}/${plugin#*/}-buildkite-plugin"
  else
    echo "buildkite-plugins/${plugin}-buildkite-plugin"
  fi
}

# gh_get <path> [gh api args...]: sets GH_OUT; returns 0 ok, 44 for HTTP 404, 1 for any other error.
gh_get() {
  local path="$1"
  shift
  if GH_OUT="$(gh api "$path" "$@" 2>&1)"; then return 0; fi
  [[ "$GH_OUT" == *"HTTP 404"* || "$GH_OUT" == *"Not Found"* ]] && return 44
  return 1
}

declare -A seen versions latest_checked
rc=0
while IFS=$'\t' read -r plugin version _file; do
  [[ -n "${plugin:-}" ]] || continue
  key="${plugin}#${version}"
  [[ -z "${seen[$key]:-}" ]] || continue
  seen[$key]=1
  case " ${versions[$plugin]:-} " in *" $version "*) ;; *) versions[$plugin]+="${versions[$plugin]:+ }$version" ;; esac

  if [[ ! "$version" =~ $SEMVER_RE ]]; then
    echo "FAIL ${key}: floating ref '${version}' - pin a published vX.Y.Z tag"
    rc=1
    continue
  fi

  repo="$(repo_for "$plugin")"
  gh_get "repos/${repo}/git/ref/tags/${version}"
  case $? in
    0) ;;
    44) echo "FAIL ${key}: tag ${version} not found in ${repo}"; rc=1; continue ;;
    *) echo "ERROR ${key}: could not verify tag (${GH_OUT//$'\n'/ })"; rc=1; continue ;;
  esac

  # A release may not exist (tag-only plugins); if it does, it must not be a draft.
  gh_get "repos/${repo}/releases/tags/${version}" --jq .draft
  case $? in
    0) if [[ "$GH_OUT" == "true" ]]; then echo "FAIL ${key}: release is a draft"; rc=1; continue; fi ;;
    44) ;; # tag-only plugin
    *) echo "ERROR ${key}: could not verify release (${GH_OUT//$'\n'/ })"; rc=1; continue ;;
  esac
  echo "ok ${key}"

  # Advisory: is this the latest published (non-draft, non-prerelease) release?
  if [[ -z "${latest_checked[$plugin]:-}" ]]; then
    latest_checked[$plugin]=1
    if gh_get "repos/${repo}/releases/latest" --jq .tag_name && [[ -n "$GH_OUT" ]]; then
      latest_checked[$plugin]="$GH_OUT"
    fi
  fi
  latest="${latest_checked[$plugin]}"
  [[ "$latest" == 1 || "$latest" == "$version" ]] || echo "WARN outdated ${plugin}: ${version} (latest ${latest})"
done

for plugin in "${!versions[@]}"; do
  [[ "${versions[$plugin]}" == *" "* ]] && echo "WARN drift ${plugin}: ${versions[$plugin]}"
done
exit "$rc"

#!/usr/bin/env bash
# Emit dry-run `trigger:` steps for pipelines whose plugin pins changed and that the
# main PR build does not already trigger. See coverage.tsv.
# stdin: plugin<TAB>version<TAB>file (pins.sh output). Prints nothing if nothing applies.
set -euo pipefail

MAP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/coverage.tsv"
# Values are written into YAML *and* re-interpolated by `buildkite-agent pipeline upload`:
# escape backslash and quote for YAML, and `$` as `$$` for the agent.
yq() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  printf '%s' "${v//\$/\$\$}"
}

declare -A changed_files emitted
while IFS=$'\t' read -r _plugin _version file; do
  [[ -n "${file:-}" ]] && changed_files[$file]=1
done

body=""
while IFS=$'\t' read -r file slug covered env; do
  [[ -z "$file" || "$file" == \#* ]] && continue
  [[ -n "${changed_files[$file]:-}" && -z "${emitted[$slug]:-}" ]] || continue
  [[ "$covered" == "true" ]] && continue
  [[ "$covered" == "main-base-only" && "${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-}" == "main" ]] && continue
  emitted[$slug]=1
  env_lines=""
  IFS=',' read -ra kvs <<<"$env"
  for kv in "${kvs[@]}"; do
    env_lines+="        ${kv%%=*}: \"${kv#*=}\""$'\n'
  done
  body+="  - label: \":mag: plugin-check dry-run ${slug}\"
    trigger: \"${slug}\"
    build:
      message: \"#$(yq "${BUILDKITE_PULL_REQUEST:-}") - plugin-check dry-run\"
      commit: \"$(yq "${BUILDKITE_COMMIT:-}")\"
      branch: \"$(yq "${BUILDKITE_BRANCH:-}")\"
      env:
${env_lines}        ELASTIC_SLACK_NOTIFICATIONS_ENABLED: \"false\"
"
done <"$MAP"

[[ -z "$body" ]] || printf 'steps:\n%s' "$body"

#!/usr/bin/env bash
# Emit dry-run `trigger:` steps for pipelines whose plugin pins changed and that the
# main PR build does not already trigger. See coverage.tsv.
# stdin: plugin<TAB>version<TAB>file (pins.sh output). Prints nothing if nothing applies.
set -euo pipefail

MAP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/coverage.tsv"
declare -A changed_files emitted
while IFS=$'\t' read -r _plugin _version file; do
  [[ -n "${file:-}" ]] && changed_files[$file]=1
done

body=""
while IFS=$'\t' read -r file slug covered env; do
  [[ -z "$file" || "$file" == \#* ]] && continue
  [[ -n "${changed_files[$file]:-}" && "$covered" != "true" && -z "${emitted[$slug]:-}" ]] || continue
  emitted[$slug]=1
  env_lines=""
  IFS=',' read -ra kvs <<<"$env"
  for kv in "${kvs[@]}"; do
    env_lines+="        ${kv%%=*}: \"${kv#*=}\""$'\n'
  done
  body+="  - label: \":mag: plugin-check dry-run ${slug}\"
    trigger: \"${slug}\"
    build:
      message: \"#${BUILDKITE_PULL_REQUEST:-} - plugin-check dry-run\"
      commit: \"${BUILDKITE_COMMIT:-}\"
      branch: \"${BUILDKITE_BRANCH:-}\"
      env:
${env_lines}        ELASTIC_SLACK_NOTIFICATIONS_ENABLED: \"false\"
"
done <"$MAP"

[[ -z "$body" ]] || printf 'steps:\n%s' "$body"

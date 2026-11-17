#!/usr/bin/env bash
# Emit a Buildkite pipeline with one synthetic probe step per changed plugin pin.
# stdin: plugin<TAB>version<TAB>file (pins.sh output). Prints nothing if stdin is empty.
# Templates: probes/<plugin with '/' -> '_'>.yml; plugins without one get no probe.
# Placeholders: __PIN__ (plugin#version) __PLUGIN__ __VERSION__ __KEY__.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/probes"
declare -A seen
body=""

while IFS=$'\t' read -r plugin version _file; do
  [[ -n "${plugin:-}" ]] || continue
  [[ -z "${seen[${plugin}#${version}]:-}" ]] || continue
  seen[${plugin}#${version}]=1

  tpl="${DIR}/${plugin//\//_}.yml"
  if [[ ! -f "$tpl" ]]; then
    # Unknown plugin config can't be guessed safely; loading it bare could fail or act.
    echo "plugin-check: no probe for ${plugin}#${version} (static tag check only)" >&2
    continue
  fi
  key="probe-$(tr -c 'A-Za-z0-9\n' '-' <<<"${plugin}-${version}")"
  body+="$(sed -e "s|__PIN__|${plugin}#${version}|g" \
    -e "s|__PLUGIN__|${plugin}|g" \
    -e "s|__VERSION__|${version}|g" \
    -e "s|__KEY__|${key}|g" "$tpl")"$'\n'
done

[[ -z "$body" ]] || printf 'steps:\n%s' "$body"

#!/bin/bash

set -euo pipefail

usage() {
  echo "Usage: $0 <go-version>"
  echo "  <go-version>: Go version without the leading v (e.g. 1.26.8)."
  exit 1
}

go_version=${1:-}
[[ -n "$go_version" ]] || {
  echo "Error: missing <go-version>" >&2
  usage
}

if ! command -v elastic-agent-changelog-tool &>/dev/null; then
  echo "Error: elastic-agent-changelog-tool must be available on PATH" >&2
  exit 2
fi

fragment_name="update-go-to-${go_version}"
echo "=> Creating changelog fragment for Go ${go_version}"
elastic-agent-changelog-tool new "Update Go to ${go_version}"

shopt -s nullglob
fragments=(changelog/fragments/*-"${fragment_name}".yaml)
shopt -u nullglob
if [[ "${#fragments[@]}" -ne 1 ]]; then
  echo "Error: expected one changelog fragment for Go ${go_version}, found ${#fragments[@]}" >&2
  exit 3
fi

fragment_path=${fragments[0]}
sed -i.bak \
  -e 's/^kind:.*/kind: enhancement/' \
  -e 's/^component:.*/component: elastic-agent/' \
  "$fragment_path"
rm "${fragment_path}.bak"

echo "=> Changelog fragment ready: ${fragment_path}"

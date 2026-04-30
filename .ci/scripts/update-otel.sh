#!/bin/bash

set -euo pipefail

usage() {
  echo "Usage: $0 <next-beta-core> <next-stable-core> [<next-contrib>]"
  echo "  <next-beta-core>: Next version of the unstable core components (e.g. v0.120.0). Get it from https://github.com/open-telemetry/opentelemetry-collector/releases."
  echo "  <next-stable-core>: Next stable version of the stable core components (e.g. v1.26.0). Get it from https://github.com/open-telemetry/opentelemetry-collector/releases."
  echo "  <next-contrib>: Next version of the contrib components (e.g. v0.120.1). Get it from https://github.com/open-telemetry/opentelemetry-collector-contrib/releases. If not specified, <next-beta-core> is used."
  echo
  exit 1
}
next_beta_core=${1:-}
[[ -n "$next_beta_core" ]] || (echo "Error: missing <next-beta-core>" && echo && usage)

next_stable_core=${2:-}
[[ -n "$next_stable_core" ]] || (echo "Error: missing <next-stable-core>" && echo && usage)

next_contrib=${3:-$next_beta_core}

GOMOD_FILES=("internal/edot/go.mod" "go.mod")

for gomod_file in "${GOMOD_FILES[@]}"; do
  # Get current versions from the go.mod
  current_beta_core=$(grep 'go\.opentelemetry\.io/collector/component/componentstatus v' "$gomod_file" | cut -d' ' -f 2 || true)
  current_stable_core=$(grep 'go\.opentelemetry\.io/collector/pdata v' "$gomod_file" | cut -d' ' -f 2 || true)
  current_contrib=$(grep 'github\.com/open-telemetry/opentelemetry-collector-contrib/pkg/status v' "$gomod_file" | cut -d' ' -f 2 || true)

  [[ -n "$current_beta_core" ]] || (echo "Error: couldn't find current beta core version." && exit 2)
  [[ -n "$current_stable_core" ]] || (echo "Error: couldn't find current stable core version" && exit 3)
  [[ -n "$current_contrib" ]] || (echo "Error: couldn't find current contrib version" && exit 4)

  echo "=> Updating core from $current_beta_core/$current_stable_core to $next_beta_core/$next_stable_core in $gomod_file"
  echo "=> Updating contrib from $current_contrib to $next_contrib in $gomod_file"

  sed -i.bak "s/\(go\.opentelemetry\.io\/collector.*\) $current_beta_core/\1 $next_beta_core/" "$gomod_file"
  sed -i.bak "s/\(go\.opentelemetry\.io\/collector.*\) $current_stable_core/\1 $next_stable_core/" "$gomod_file"
  sed -i.bak "s/\(github\.com\/open-telemetry\/opentelemetry\-collector\-contrib\/.*\) $current_contrib/\1 $next_contrib/" "$gomod_file"
  rm "${gomod_file}.bak"
done

# Update elastic/opentelemetry-collector-components in internal/edot/go.mod.
# Find the latest release of each submodule whose go.mod uses the new OTel versions.
EDOT_GOMOD="internal/edot/go.mod"

if grep -q 'github\.com/elastic/opentelemetry-collector-components/' "$EDOT_GOMOD"; then
  echo "=> Updating elastic/opentelemetry-collector-components to a version compatible with OTel ${next_beta_core}/${next_stable_core}"

  if ! command -v curl &>/dev/null; then
    echo "Error: curl is required to look up elastic/opentelemetry-collector-components versions" >&2
    exit 5
  fi
  if ! command -v jq &>/dev/null; then
    echo "Error: jq is required to look up elastic/opentelemetry-collector-components versions" >&2
    exit 6
  fi

  # Issue GitHub API requests, using GITHUB_TOKEN for authentication if available.
  curl_github() {
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      curl -sf -H "Authorization: Bearer $GITHUB_TOKEN" "$@"
    else
      curl -sf "$@"
    fi
  }

  echo "=> Fetching tags from elastic/opentelemetry-collector-components"
  elastic_components_tags=""
  page=1
  while true; do
    page_tags=$(curl_github \
      "https://api.github.com/repos/elastic/opentelemetry-collector-components/tags?per_page=100&page=${page}" | \
      jq -r '.[].name') || {
      echo "Error: could not fetch tags from GitHub API for elastic/opentelemetry-collector-components" >&2
      exit 7
    }
    [[ -n "$page_tags" ]] || break
    elastic_components_tags+="${page_tags}"$'\n'
    page=$((page + 1))
  done

  # Find the latest released version (vX.Y.Z) of a submodule whose go.mod depends on
  # either of the target OTel versions. Uses the global $elastic_components_tags variable.
  # Checks module-specific tags (e.g. connector/elasticapmconnector/vX.Y.Z) first,
  # then falls back to repo-level tags (vX.Y.Z) for modules that share a monolithic tag.
  find_elastic_components_version() {
    local module_subpath="$1"   # e.g. "connector/elasticapmconnector"
    local target_beta="$2"      # e.g. "v0.149.0"
    local target_stable="$3"    # e.g. "v1.55.0"
    local tag_prefix="${module_subpath}/v"

    _check_gomod_otel_version() {
      local gomod_ref="$1"   # git ref (tag) to fetch the go.mod from
      local gomod_path="$2"  # path within the repo
      local gomod
      gomod=$(curl_github \
        "https://raw.githubusercontent.com/elastic/opentelemetry-collector-components/${gomod_ref}/${gomod_path}/go.mod" \
        2>/dev/null) || return 1
      # If the module has no OTel collector deps it is trivially compatible with any OTel version
      if ! echo "$gomod" | grep -q "go\.opentelemetry\.io/collector"; then
        return 0
      fi
      echo "$gomod" | grep -q "go\.opentelemetry\.io/collector.* ${target_beta}" || \
      echo "$gomod" | grep -q "go\.opentelemetry\.io/collector.* ${target_stable}"
    }

    # Try module-specific tags first
    local module_tags
    module_tags=$(echo "$elastic_components_tags" | grep "^${tag_prefix}" | sort -rV)

    if [[ -n "$module_tags" ]]; then
      local tag version
      while IFS= read -r tag; do
        version="${tag#${tag_prefix}}"
        [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        if _check_gomod_otel_version "$tag" "$module_subpath"; then
          echo "v${version}"
          return 0
        fi
      done <<< "$module_tags"
    fi

    # Fall back to repo-level tags (vX.Y.Z without a subpath prefix)
    local repo_tags
    repo_tags=$(echo "$elastic_components_tags" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV)

    if [[ -n "$repo_tags" ]]; then
      local tag
      while IFS= read -r tag; do
        if _check_gomod_otel_version "$tag" "$module_subpath"; then
          echo "$tag"
          return 0
        fi
      done <<< "$repo_tags"
    fi

    echo "Error: no version of ${module_subpath} found that uses OTel ${target_beta}/${target_stable}" >&2
    return 1
  }

  # Update each non-pseudoversion elastic component module independently,
  # since different modules can have different latest versions.
  while IFS=' ' read -r module_path old_version; do
    module_subpath="${module_path#github.com/elastic/opentelemetry-collector-components/}"

    echo "=> Looking up new version for ${module_subpath} (currently at ${old_version})"

    if ! new_version=$(find_elastic_components_version \
        "$module_subpath" "$next_beta_core" "$next_stable_core"); then
      echo "Error: could not find a compatible version for ${module_subpath}" >&2
      exit 8
    fi

    if [[ "$old_version" == "$new_version" ]]; then
      echo "=> ${module_subpath} is already at ${old_version}, skipping"
    else
      echo "=> Updating ${module_subpath} from ${old_version} to ${new_version}"
      escaped_path=$(printf '%s' "$module_path" | sed 's/[.]/\\./g')
      sed -i.bak "s|${escaped_path} ${old_version}|${module_path} ${new_version}|" "$EDOT_GOMOD"
      rm "${EDOT_GOMOD}.bak"
    fi
  done < <(grep 'github\.com/elastic/opentelemetry-collector-components/' "$EDOT_GOMOD" | \
    grep -vE '\bv0\.0\.0-' | \
    awk '{print $1, $2}')
fi

echo "=> Running go mod tidy"
go mod tidy
echo "=> Running mage notice"
mage notice
echo "=> Running mage otel:readme"
mage otel:readme

echo "=> Creating changelog fragment"
changelog_fragment_name="update-otel-components-to-$next_contrib"
if command -v elastic-agent-changelog-tool &>/dev/null; then
  echo "=> Using elastic-agent-changelog-tool to create changelog fragment"
else
  echo "=> elastic-agent-changelog-tool not found, installing it"
  go install github.com/elastic/elastic-agent-changelog-tool@latest
fi
elastic-agent-changelog-tool new "$changelog_fragment_name"
sed -i.bak "s/^kind:.*$/kind: enhancement/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
sed -i.bak "s/^summary:.*$/summary: Update OTel Collector components to ${next_contrib}/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
sed -i.bak "s/^component:.*$/component: elastic-agent/" ./changelog/fragments/*-"${changelog_fragment_name}".yaml
rm ./changelog/fragments/*-"${changelog_fragment_name}".yaml.bak

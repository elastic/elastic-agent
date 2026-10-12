#!/usr/bin/env bash
# Deletes stale branches: no open PR with the branch as its head, last commit older than
# STALE_MONTHS months, not protected, not the default branch, and not matching a release
# version pattern (N.N, N.x, N.N.N, release/*).
#
# Env: GH_TOKEN, REPO (owner/name), STALE_MONTHS (default 6), DRY_RUN (default true)
set -euo pipefail

REPO="${REPO:?REPO is required}"
STALE_MONTHS="${STALE_MONTHS:-6}"
DRY_RUN="${DRY_RUN:-true}"
OWNER="${REPO%%/*}"
NAME="${REPO##*/}"

if date --version >/dev/null 2>&1; then
  CUTOFF="$(date -u -d "${STALE_MONTHS} months ago" +%Y-%m-%dT%H:%M:%SZ)"
else
  CUTOFF="$(date -u -v-"${STALE_MONTHS}"m +%Y-%m-%dT%H:%M:%SZ)"
fi
echo "Repo: ${REPO} | cutoff: ${CUTOFF} | dry run: ${DRY_RUN}"

DEFAULT_BRANCH="$(gh api "repos/${REPO}" --jq .default_branch)"

# Head branches of open PRs that live in this repo (fork PRs can't reference our branches).
OPEN_PR_BRANCHES="$(gh pr list -R "${REPO}" --state open --limit 5000 \
  --json headRefName,isCrossRepository --jq '.[] | select(.isCrossRepository | not) | .headRefName')"

# Branch name, last commit date, protected flag.
BRANCHES="$(gh api graphql --paginate \
  -f owner="${OWNER}" -f name="${NAME}" \
  -f query='query($owner:String!,$name:String!,$endCursor:String){
    repository(owner:$owner,name:$name){
      refs(refPrefix:"refs/heads/",first:100,after:$endCursor){
        pageInfo{hasNextPage endCursor}
        nodes{name branchProtectionRule{id} target{... on Commit{committedDate}}}
      }
    }
  }' --jq '.data.repository.refs.nodes[] | [.name, .target.committedDate, (.branchProtectionRule != null)] | @tsv')"

RELEASE_RE='^([0-9]+\.([0-9]+|x)(\.[0-9]+)?|release/.*)$'
deleted=0
while IFS=$'\t' read -r branch date protected; do
  [[ -z "${branch}" ]] && continue
  [[ "${branch}" == "${DEFAULT_BRANCH}" ]] && continue
  [[ "${protected}" == "true" ]] && continue
  [[ "${branch}" =~ ${RELEASE_RE} ]] && continue
  [[ ! "${date}" < "${CUTOFF}" ]] && continue
  if grep -Fxq -- "${branch}" <<<"${OPEN_PR_BRANCHES}"; then continue; fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[dry-run] would delete ${branch} (last commit ${date})"
  else
    echo "Deleting ${branch} (last commit ${date})"
    # Branch names may contain slashes, which gh api passes through as-is in the ref path.
    # A failure (e.g. a ruleset-protected branch) is reported but doesn't stop the run.
    gh api -X DELETE "repos/${REPO}/git/refs/heads/${branch}" >/dev/null \
      || { echo "::warning::Failed to delete ${branch}"; continue; }
  fi
  deleted=$((deleted + 1))
done <<<"${BRANCHES}"

echo "Stale branches $([[ "${DRY_RUN}" == "true" ]] && echo "found" || echo "deleted"): ${deleted}"

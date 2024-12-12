#!/bin/bash
set -e

package_version=$(mage integration:updatePackageVersion)
version_requirements=$(mage integration:updateVersions)
changes=$(git status -s -uno testing/integration/testdata/.upgrade-test-agent-versions.yml .package-version)
if [ -z "$changes" ]
then
    echo "The version files didn't change, skipping..."
else
		# because this script is running on the matrix, we need to fetch the current branch on every run
		current_ref=$(git rev-parse --abbrev-ref HEAD)
    echo "The version file(s) changed"
    git diff -p
    open=$(gh pr list --repo "$GITHUB_REPOSITORY" --label="update-versions" --limit 1 --state open --base "$current_ref")
    if [ -n "$open" ]
    then
        echo "Another PR for $current_ref is in review, skipping..."
        exit 0
    fi
		pr_branch="$current_ref-update-agent-versions-$GITHUB_RUN_ID"
    # the mage target above requires to be on a release branch
    # so, the new branch should not be created before the target is run
    git checkout -b "$pr_branch"
    git add testing/integration/testdata/.upgrade-test-agent-versions.yml .package-version

    nl=$'\n' # otherwise the new line character is not recognized properly
    commit_desc="These files are used for picking the starting (pre-upgrade) or ending (post-upgrade) agent versions in upgrade integration tests.${nl}${nl}The content is based on responses from https://www.elastic.co/api/product_versions and https://snapshots.elastic.co${nl}${nl}The current update is generated based on the following requirements:${nl}${nl}Package version: ${package_version}${nl}${nl}\`\`\`json${nl}${version_requirements}${nl}\`\`\`"

    git commit -m "[$current_ref][Automation] Update versions" -m "$commit_desc"
    git push --set-upstream origin "$pr_branch"
    pr=$(gh pr create \
       --base "$current_ref" \
       --fill-first \
       --head "$pr_branch" \
       --label 'Team:Elastic-Agent' \
       --label 'Team:Elastic-Agent-Control-Plane' \
       --label 'update-versions' \
       --label 'skip-changelog' \
       --label 'backport-skip' \
       --repo $GITHUB_REPOSITORY)
    echo "pr=$pr" >> "$GITHUB_OUTPUT" # set the step output for Slack notifications
    echo "Created a PR with the an update: $pr"
fi

#!/bin/bash
set -e

package_version=$(mage integration:updatePackageVersion)
version_requirements=$(mage integration:updateVersions)
changes=$(git status -s -uno .agent-versions.json .package-version)
if [ -z "$changes" ]
then
    echo "The version files didn't change, skipping..."
else
    echo "The version file(s) changed"
    git diff -p
    open=$(gh pr list --repo "$GITHUB_REPOSITORY" --label="update-versions" --limit 1 --state open --base "$GITHUB_REF_NAME")
    if [ -n "$open" ]
    then
        echo "Another PR for $GITHUB_REF_NAME is in review, skipping..."
        exit 0
    fi
    # the mage target above requires to be on a release branch
    # so, the new branch should not be created before the target is run
    git checkout -b update-agent-versions-$GITHUB_RUN_ID
    git add .agent-versions.json .package-version

    nl=$'\n' # otherwise the new line character is not recognized properly
    commit_desc="These files are used for picking the starting (pre-upgrade) or ending (post-upgrade) agent versions in upgrade integration tests.${nl}${nl}The content is based on responses from https://www.elastic.co/api/product_versions and https://snapshots.elastic.co${nl}${nl}The current update is generated based on the following requirements:${nl}${nl}Package version: ${package_version}${nl}${nl}\`\`\`json${nl}${version_requirements}${nl}\`\`\`"

    git commit -m "[$GITHUB_REF_NAME][Automation] Update versions" -m "$commit_desc"
    git push --set-upstream origin "update-agent-versions-$GITHUB_RUN_ID"
    pr=$(gh pr create \
       --base "$GITHUB_REF_NAME" \
       --fill-first \
       --head "update-agent-versions-$GITHUB_RUN_ID" \
       --label 'Team:Elastic-Agent' \
       --label 'Team:Elastic-Agent-Control-Plane' \
       --label 'update-versions' \
       --label 'skip-changelog' \
       --label 'backport-skip' \
       --repo $GITHUB_REPOSITORY)
    echo "pr=$pr" >> "$GITHUB_OUTPUT" # set the step output for Slack notifications
    echo "Created a PR with the an update: $pr"
fi

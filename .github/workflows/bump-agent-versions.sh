#!/bin/bash
set -e

version_requirements=$(mage integration:updateVersions)
changes=$(git status -s -uno .agent-versions.json)
if [ -z "$changes" ]
then
    echo "The versions file didn't change, skipping..."
else
    echo "The versions file changed"
    open=$(gh pr list --repo "$GITHUB_REPOSITORY" --label="update-versions" --limit 1 --state open --base "$GITHUB_REF_NAME")
    if [ -n "$open" ]
    then
        echo "Another PR for $GITHUB_REF_NAME is in review, skipping..."
        exit 0
    fi
    git diff -p
    git add ".agent-versions.json"

		nl=$'\n' # otherwise the new line character is not recognized properly
		commit_desc="This file is used for picking agent versions in integration tests.${nl}${nl}The file's content is based on responses from https://www.elastic.co/api/product_versions and https://snapshots.elastic.co${nl}${nl}The current update is generated based on the following requirements:${nl}${nl}\`\`\`json${nl}${version_requirements}${nl}\`\`\`"

		git commit -m "[$GITHUB_REF_NAME][Automation] Update .agent-versions.json" -m "$commit_desc"
    git push --set-upstream origin "update-agent-versions-$GITHUB_RUN_ID"
    gh pr create \
       --base "$GITHUB_REF_NAME" \
       --fill-first \
       --head "update-agent-versions-$GITHUB_RUN_ID" \
       --label 'Team:Elastic-Agent' \
       --label 'update-versions' \
       --label 'skip-changelog' \
       --label 'backport-skip' \
       --repo $GITHUB_REPOSITORY
fi

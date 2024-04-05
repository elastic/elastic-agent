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
    git commit -m "[$GITHUB_REF_NAME](automation) Update .agent-versions.json" -m "This file is used for picking agent versions in integration tests.\n\nThe file's content is based on responses from https://www.elastic.co/api/product_versions and https://snapshots.elastic.co\n\nThe current update is generated based on the following requirements:\n\`\`\`json\n$version_requirements\n\`\`\`"
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

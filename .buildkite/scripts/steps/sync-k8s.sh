#!/bin/bash
set -euo pipefail

export PATH=$HOME/bin:${PATH}

source .buildkite/scripts/install-gh.sh
source .buildkite/scripts/common.sh

echo "--- [Prepare env] Create required env variables"
GITHUB_USERNAME_SECRET="elasticmachine"
export GITHUB_USERNAME_SECRET=$GITHUB_USERNAME_SECRET
export GITHUB_EMAIL_SECRET="elasticmachine@elastic.co"
export GITHUB_TOKEN_SECRET=$VAULT_GITHUB_TOKEN

cd deploy/kubernetes

echo "--- [File Creation] Create-Needed-Manifest"
WITHOUTCONFIG=true make generate-k8s
./creator_k8s_manifest.sh .

echo "--- [Clone] Kibana-Repository"
make ci-clone-kibana-repository
cp Makefile ./kibana
cd kibana
echo "--- Create Kibana PR"
make ci-create-kubernetes-templates-pull-request


#!/bin/bash
set -euo pipefail

export PATH=$HOME/bin:${PATH}

source .buildkite/scripts/install-gh.sh
source .buildkite/scripts/common.sh

echo "--- [Prepare env] Create required env variables"
GITHUB_TOKEN_VAULT_PATH="kv/ci-shared/platform-ingest/github_token"
GITHUB_USERNAME_SECRET=$(retry 5 vault kv get -field username ${GITHUB_TOKEN_VAULT_PATH})
export GITHUB_USERNAME_SECRET
GITHUB_EMAIL_SECRET=$(retry 5 vault kv get -field email ${GITHUB_TOKEN_VAULT_PATH})
export GITHUB_EMAIL_SECRET
GITHUB_TOKEN_SECRET=$(retry 5 vault kv get -field token ${GITHUB_TOKEN_VAULT_PATH})
export GITHUB_TOKEN_SECRET

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

echo "--- [File Update] Kustomize-Tempates"
GENERATEKUSTOMIZE=true make ci-create-kustomize 
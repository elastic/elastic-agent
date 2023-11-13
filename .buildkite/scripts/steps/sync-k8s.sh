#!/bin/bash
set -euo pipefail

export PATH=$HOME/bin:${PATH}
source .buildkite/scripts/install-gh.sh


cd deploy/kubernetes

echo "--- [File Creation] Create-Needed-Manifest"
WITHOUTCONFIG=true make generate-k8s
./creator_k8s_manifest.sh .

echo "--- [Clone] Kibana-Repository"
make ci-clone-kibana-repository
cp Makefile ./kibana
cd kibana
make ci-create-kubernetes-templates-pull-request
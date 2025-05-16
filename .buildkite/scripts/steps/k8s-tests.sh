#!/bin/bash
set -euo pipefail

export PATH=$HOME/bin:${PATH}
source .buildkite/scripts/install-kubectl.sh
source .buildkite/scripts/install-kind.sh

kind create cluster --image "kindest/node:${K8S_VERSION}" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiVersion: kubeadm.k8s.io/v1beta4
    scheduler:
      extraArgs:
      - name: bind-address
        value: 0.0.0.0
      - name: port
        value: "10251"
      - name: secure-port
        value: "10259"
    controllerManager:
      extraArgs:
      - name: bind-address
        value: 0.0.0.0
      - name: port
        value: "10252"
      - name: secure-port
        value: "10257"
EOF
kubectl cluster-info


make -C deploy/kubernetes test
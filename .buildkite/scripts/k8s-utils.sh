#!/usr/bin/env bash

# openshift_to_k8s_version prints the Kubernetes version shipped by an OpenShift release.
openshift_to_k8s_version() {
  local openshift_version="${1#v}"
  local major minor
  IFS=. read -r major minor _ <<< "${openshift_version}"

  case "${major}.${minor}" in
    4.20) echo "v1.33.0" ;;
    4.21) echo "v1.34.0" ;;
    4.22) echo "v1.35.0" ;;
    *)
      >&2 echo "No Kubernetes version mapped for OpenShift version $1"
      return 1
      ;;
  esac
}

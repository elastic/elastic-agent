#!/usr/bin/env bash
# Runs the custom CA browser tests (internal/pkg/customca) inside the freshly built
# complete images, once as a regular user and once as root, so they check what is
# really shipped: certutil, the NSS database and a browser that trusts it.
set -euo pipefail

source .buildkite/scripts/retry.sh

# Make sure that all tools are installed
retry 3 asdf install

mkdir -p build
CGO_ENABLED=0 go test -c -tags integration -o build/customca.test ./internal/pkg/customca

shopt -s nullglob
tarballs=(build/distributions/*complete*-linux-amd64.docker.tar.gz)
if [[ ${#tarballs[@]} -eq 0 ]]; then
  echo "Error: no complete image found in build/distributions" >&2
  exit 1
fi

for tarball in "${tarballs[@]}"; do
  image=$(docker load -i "$tarball" | sed -n 's/^Loaded image: //p' | head -1)
  for uid in 1000 0; do
    echo "--- ${image} as uid ${uid}"
    docker run --rm -u "${uid}" -e HOME=/usr/share/elastic-agent \
      -v "${PWD}/build/customca.test:/customca.test:ro" \
      --entrypoint /customca.test "${image}" \
      -test.v -test.run 'TestBrowserTrustsMountedCA|TestSyncWithRealCertutil'
  done
done

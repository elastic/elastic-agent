#!/usr/bin/env bash
# Sourced from .buildkite/hooks/pre-command.
#
# Configures GOCACHEPROG (https://github.com/platacard/cacheprog) so that the
# Go build cache is read from and written to S3 directly, object by object.
# There is no per-job archive to download, unpack, repack and upload: the Go
# toolchain asks cacheprog for each action ID and only misses are compiled.
#
# A step opts in by adding the elastic/oblt-aws-auth plugin, which provides the
# AWS credentials cacheprog uses. The plugin's pre-command hook runs after this
# one, but that's fine: cacheprog is only started by `go` in the command phase.
# The plugin is added to the packaging steps (.buildkite/integration.pipeline.yml),
# where the cross-build of the agent, the EDOT collector and the osquery
# extension dominates the step time. It is not worth adding to the test steps:
# they only compile a test binary and the gain was within the noise.
#
# Objects live in the elastic-agent-ci-go-cache bucket (defined in oblt-infra,
# conf/resources/repos/elastic-agent/01-aws-bucket.tf) under a prefix keyed by
# the Go version, so a toolchain bump starts from a fresh namespace and the
# objects of the previous toolchain stop being written to and expire. Expiry
# is handled by a bucket lifecycle rule on the go-build/ prefix; cacheprog does
# not delete anything itself.
#
# Every build reads from and writes to the cache, so a pull request benefits
# from its own earlier builds as well as from the builds of main. The cache is
# content addressed (objects are keyed by the hash of their inputs) and only
# builds of this pipeline can write to the bucket. Set GO_BUILD_CACHE_READ_ONLY
# to "true" on a step to restore without writing (CACHEPROG_DISABLE_PUT), for
# example to keep experiments from populating the shared cache.
#
# If anything here fails, we leave GOCACHEPROG unset and Go falls back to the
# local GOCACHE, so a cache problem never fails a build.

CACHEPROG_VERSION="v1.3.1"

setup_cacheprog() {
  if [[ "${BUILDKITE_PLUGINS:-}" != *"oblt-aws-auth"* ]]; then
    return 0
  fi
  if [[ -z "${GO_VERSION:-}" ]]; then
    echo "cacheprog: GO_VERSION is not set, falling back to the local GOCACHE"
    return 0
  fi

  echo "--- Setting up cacheprog ${CACHEPROG_VERSION} for the Go build cache"

  local os arch sha256
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$(uname -m)" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *)
      echo "cacheprog: unsupported architecture $(uname -m), skipping"
      return 0
      ;;
  esac
  # From https://github.com/platacard/cacheprog/releases/download/${CACHEPROG_VERSION}/checksums.txt
  case "${os}_${arch}" in
    linux_amd64) sha256="74270f59b23a0e6d20a7606d44cb81729af3a54cfbc5718aab1c608fa3c938cc" ;;
    linux_arm64) sha256="7b3e90792534f5256b290e56ab6dcaf4132fda112046487da1379b2ce2456761" ;;
    darwin_amd64) sha256="866c175ce4de774a474a7256c1c9ae1563dae47254e41aa33a8261426704442b" ;;
    darwin_arm64) sha256="860c726f0678aefe32f118a5d49219b469dc2d89062b9e35be80ef93a8778990" ;;
    *)
      echo "cacheprog: unsupported platform ${os}_${arch}, skipping"
      return 0
      ;;
  esac

  # Per-user directory: scripts that re-source the pre-command hook as root
  # (sudo integration tests) must not leave root-owned files in the way of the
  # non-root user.
  local dir
  dir="${TMPDIR:-/tmp}/cacheprog-${CACHEPROG_VERSION}-$(id -u)"
  local bin="${dir}/cacheprog"
  if [[ ! -x "${bin}" ]]; then
    local archive="cacheprog_${CACHEPROG_VERSION}_${os}_${arch}.tar.gz"
    mkdir -p "${dir}"
    if ! retry 3 curl -sSfL -o "${dir}/${archive}" \
      "https://github.com/platacard/cacheprog/releases/download/${CACHEPROG_VERSION}/${archive}"; then
      echo "cacheprog: download failed, falling back to the local GOCACHE"
      return 0
    fi
    local sha256_cmd=(sha256sum)
    if ! command -v sha256sum >/dev/null; then
      sha256_cmd=(shasum -a 256) # macOS
    fi
    if ! echo "${sha256}  ${dir}/${archive}" | "${sha256_cmd[@]}" -c -; then
      echo "cacheprog: checksum mismatch, falling back to the local GOCACHE"
      return 0
    fi
    if ! tar -xzf "${dir}/${archive}" -C "${dir}" cacheprog; then
      echo "cacheprog: extraction failed, falling back to the local GOCACHE"
      return 0
    fi
    rm -f "${dir}/${archive}"
  fi

  # Logging to stderr would clutter every `go` command's output, so send it
  # to a file; the pre-exit hook prints a summary of the statistics.
  # --log-output can't be used for this: in v1.3.x it opens the file but
  # still logs to stderr.
  # AUTOMEMLIMIT=off stops cacheprog from trying to derive GOMEMLIMIT from
  # cgroups, which logs errors where there are none (macOS, Windows). It's
  # set only for cacheprog: EDOT components under test use the same library.
  # GODEBUG is cleared because FIPS builds and tests run `go` with
  # GODEBUG=fips140=only, which cacheprog inherits, and it then can't compute
  # the MD5 sums S3 requires. cacheprog is CI tooling, not the product under
  # test, so running it outside FIPS mode is fine.
  local log="${dir}/cacheprog.log"
  local wrapper="${dir}/cacheprog-wrapper"
  printf '#!/bin/sh\nunset GODEBUG\nAUTOMEMLIMIT=off exec "%s" "$@" 2>>"%s"\n' "${bin}" "${log}" >"${wrapper}"
  chmod +x "${wrapper}"

  # The golang-crossbuild containers started by mage (see
  # dev-tools/mage/crossbuild.go) get this directory mounted at /cacheprog, so
  # the wrapper and log use container paths. The log and the local object dir
  # must be writable by whichever user the container runs as.
  if [[ "${os}" == "linux" ]]; then
    local container_wrapper="${dir}/cacheprog-wrapper-container"
    printf '#!/bin/sh\nunset GODEBUG\nAUTOMEMLIMIT=off exec /cacheprog/cacheprog "$@" 2>>/cacheprog/cacheprog-container.log\n' >"${container_wrapper}"
    chmod +x "${container_wrapper}"
    chmod a+rx "${bin}"
    touch "${dir}/cacheprog-container.log"
    chmod 666 "${dir}/cacheprog-container.log"
    mkdir -p "${dir}/disk-container"
    chmod 777 "${dir}/disk-container"
    export CACHEPROG_CROSSBUILD_DIR="${dir}"
  fi

  export GOCACHEPROG="${wrapper}"
  export CI_CACHEPROG_LOG="${log}"
  export CACHEPROG_REMOTE_STORAGE_TYPE="s3"
  export CACHEPROG_S3_BUCKET="elastic-agent-ci-go-cache"
  # Set explicitly: the CI role isn't allowed to call GetBucketLocation.
  export CACHEPROG_S3_REGION="us-east-1"
  # Keyed by Go version, see the header. The bucket lifecycle rule expires
  # everything under go-build/ that has not been rewritten for a while, so
  # abandoned toolchain namespaces clean themselves up. Kept a plain string
  # rather than a cacheprog template, so the crossbuild containers (which get
  # the CACHEPROG_* variables but not GO_VERSION) use the same prefix.
  export CACHEPROG_S3_PREFIX="go-build/go${GO_VERSION}"
  # Opt-out knob for steps that should restore but not write, see the header.
  if [[ "${GO_BUILD_CACHE_READ_ONLY:-false}" == "true" ]]; then
    export CACHEPROG_DISABLE_PUT="true"
  fi
  # Persistent per-user dir so objects survive across builds on the same agent
  # (cacheprog has no pruning; agent recycling bounds the growth). It must be a
  # single absolute path, otherwise cacheprog silently falls back to a separate
  # temp dir per process. Don't derive it from `go env GOCACHE`: in this hook
  # the asdf shim prints extra lines on stdout.
  local cache_base="${XDG_CACHE_HOME:-${HOME:-}/.cache}"
  if [[ "${os}" == "darwin" ]]; then
    cache_base="${HOME:-}/Library/Caches"
  fi
  if [[ "${cache_base}" == /* ]]; then
    export CACHEPROG_ROOT_DIRECTORY="${cache_base}/cacheprog"
  else
    export CACHEPROG_ROOT_DIRECTORY="${dir}/disk"
  fi

  echo "GOCACHEPROG=${GOCACHEPROG} (prefix ${CACHEPROG_S3_PREFIX}, writes ${CACHEPROG_DISABLE_PUT:+disabled}${CACHEPROG_DISABLE_PUT:-enabled})"
}

setup_cacheprog

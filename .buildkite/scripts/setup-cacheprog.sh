#!/usr/bin/env bash
# Sourced from .buildkite/hooks/pre-command.
#
# Configures GOCACHEPROG (https://github.com/platacard/cacheprog) so that the
# Go build cache is read from and written to S3 directly, object by object.
#
# A step opts in by adding the elastic/oblt-aws-auth plugin, which provides the
# AWS credentials cacheprog uses. The plugin's pre-command hook runs after this
# one, but that's fine: cacheprog is only started by `go` in the command phase.
#
# If anything here fails, we leave GOCACHEPROG unset and Go falls back to the
# local GOCACHE, so a cache problem never fails a build.

CACHEPROG_VERSION="v1.3.0"

setup_cacheprog() {
  if [[ "${BUILDKITE_PLUGINS:-}" != *"oblt-aws-auth"* ]]; then
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
  case "${os}_${arch}" in
    linux_amd64) sha256="b5942a1b65a97535dfd980d8c53fd54097505f036bc3210daaec58fe170ecf3a" ;;
    linux_arm64) sha256="24072288d0bd14dccb3c8207632bbecfbfffadbb42f383a7bed555ce858a19d0" ;;
    darwin_amd64) sha256="abe3a0abd6465cc7c5a6fb3a52f464f521e5222b71fd9017f68bb9f4d1d90d4f" ;;
    darwin_arm64) sha256="ebe7cc4d04a40cb788cdffceed08b65c1bd209c41b4589dd01a9aaf208a92acf" ;;
    *)
      echo "cacheprog: unsupported platform ${os}_${arch}, skipping"
      return 0
      ;;
  esac

  # Per-user directory: the sudo integration tests re-source the pre-command
  # hook as root, and root-owned files here would break the non-root user.
  local dir="${TMPDIR:-/tmp}/cacheprog-${CACHEPROG_VERSION}-$(id -u)"
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
  # --log-output can't be used for this: in v1.3.0 it opens the file but
  # still logs to stderr.
  # AUTOMEMLIMIT=off stops cacheprog from trying to derive GOMEMLIMIT from
  # cgroups, which logs errors where there are none (macOS, Windows). It's
  # set only for cacheprog: EDOT components under test use the same library.
  # GODEBUG is cleared because the FIPS unit tests run `go test` with
  # GODEBUG=fips140=only, which cacheprog inherits, and it then can't compute
  # the MD5 sums S3 requires. cacheprog is CI tooling, not the product under
  # test, so running it outside FIPS mode is fine.
  local log="${dir}/cacheprog.log"
  local wrapper="${dir}/cacheprog-wrapper"
  printf '#!/bin/sh\nunset GODEBUG\nAUTOMEMLIMIT=off exec "%s" "$@" 2>>"%s"\n' "${bin}" "${log}" >"${wrapper}"
  chmod +x "${wrapper}"

  export GOCACHEPROG="${wrapper}"
  export CI_CACHEPROG_LOG="${log}"
  export CACHEPROG_REMOTE_STORAGE_TYPE="s3"
  export CACHEPROG_S3_BUCKET="elastic-agent-ci-go-cache"
  # Set explicitly: the CI role isn't allowed to call GetBucketLocation.
  export CACHEPROG_S3_REGION="us-east-1"
  # PoC-only prefix. Objects under it are meant to be removed after 1 day by
  # a bucket lifecycle rule; the Expires header alone doesn't delete anything.
  export CACHEPROG_S3_PREFIX="cacheprog-poc"
  export CACHEPROG_S3_EXPIRATION="24h"
  # Use a persistent sibling of GOCACHE so objects survive across builds on the
  # same agent. Separate from GOCACHE itself to avoid interfering with Go's own
  # cache GC (cacheprog has no pruning; the agent recycle bounds disk growth).
  # Falls back to a job-scoped temp dir if GOCACHE is unset or off.
  local gocache_dir="${GOCACHE:-$(go env GOCACHE 2>/dev/null)}"
  if [[ -n "${gocache_dir}" && "${gocache_dir}" != "off" ]]; then
    export CACHEPROG_ROOT_DIRECTORY="${gocache_dir}-cacheprog"
  else
    export CACHEPROG_ROOT_DIRECTORY="${dir}/disk"
  fi

  echo "GOCACHEPROG=${GOCACHEPROG}"
}

setup_cacheprog

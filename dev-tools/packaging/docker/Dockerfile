# User/group args
ARG ELASTIC_AGENT_USER="elastic-agent"
ARG ELASTIC_AGENT_UID=1000
ARG ELASTIC_AGENT_GID=1000

# beats stuff
ARG BEAT_NAME="elastic-agent"
ARG BEAT_HOME="/usr/share/${BEAT_NAME}"
ARG HOST_BEAT_HOME="beat"
ARG BEAT_VENDOR
ARG BEAT_VERSION
ARG BEAT_URL
ARG BEAT_DESCRIPTION
ARG BEAT_ROOT_IMPORT_PATH
ARG BEAT_COMMIT
ARG BEAT_COMMIT_SHORT
ARG BEAT_LICENSE

#docker image stuff
ARG BASE_IMAGE_FAMILY="ubuntu"
ARG BUILD_TIMESTAMP

# Base images args

# Ubuntu
ARG UBUNTU_BASE_VERSION="24.04"

# Wolfi
ARG WOLFI_BASE_IMAGE="cgr.dev/chainguard/wolfi-base"
ARG WOLFI_BASE_VERSION="latest"


# Base images

## Ubuntu
FROM ubuntu:${UBUNTU_BASE_VERSION} AS elastic_agent_base_ubuntu

ENV BEAT_SETUID_AS=elastic-agent
# Delete the existing "ubuntu" user to prevent conflict with the user that is added later.
# See https://bugs.launchpad.net/cloud-images/+bug/2005129/comments/2.
RUN touch /var/mail/ubuntu && \
      chown ubuntu /var/mail/ubuntu && \
      userdel -r ubuntu && \
      apt-get update -y && \
      DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes ca-certificates curl gawk xz-utils && \
      apt-get clean all

# Add an init process, check the checksum to make sure it's a match
RUN set -e ; \
  TINI_BIN=""; \
  TINI_SHA256=""; \
  TINI_VERSION="v0.19.0"; \
  case "$(arch)" in \
    x86_64) \
      TINI_BIN="tini-amd64"; \
      TINI_SHA256="93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c"; \
      ;; \
    aarch64) \
      TINI_BIN="tini-arm64"; \
      TINI_SHA256="07952557df20bfd2a95f9bef198b445e006171969499a1d361bd9e6f8e5e0e81"; \
      ;; \
    *) \
      echo >&2 ; echo >&2 "Unsupported architecture \$(arch)" ; echo >&2 ; exit 1 ; \
      ;; \
  esac ; \
  curl --retry 8 -S -L -O "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/${TINI_BIN}" ; \
  echo "${TINI_SHA256} ${TINI_BIN}" | sha256sum -c - ; \
  mv "${TINI_BIN}" /usr/bin/tini ; \
  chmod +x /usr/bin/tini


## Wolfi
FROM ${WOLFI_BASE_IMAGE}:${WOLFI_BASE_VERSION} AS elastic_agent_base_wolfi
RUN apk update && \
    apk add --no-cache shadow libcap-utils


# Elastic Agent images
FROM elastic_agent_base_${BASE_IMAGE_FAMILY} AS elastic_agent_image

COPY ${HOST_BEAT_HOME} ${BEAT_HOME}

LABEL \
  org.label-schema.build-date="${BUILD_TIMESTAMP}" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.vendor="${BEAT_VENDOR}" \
  org.label-schema.license="${BEAT_LICENSE}" \
  org.label-schema.name="${BEAT_NAME}" \
  org.label-schema.version="${BEAT_VERSION}" \
  org.label-schema.url="${BEAT_URL}" \
  org.label-schema.vcs-url="${BEAT_ROOT_IMPORT_PATH}" \
  org.label-schema.vcs-ref="${BEAT_VCS_REF}" \
  io.k8s.description="${BEAT_DESCRIPTION}" \
  io.k8s.display-name="${BEAT_NAME} image" \
  org.opencontainers.image.created="${BUILD_TIMESTAMP}" \
  org.opencontainers.image.licenses="${BEAT_LICENSE}" \
  org.opencontainers.image.title="${BEAT_NAME}" \
  org.opencontainers.image.vendor="${BEAT_VENDOR}" \
  org.opencontainers.image.authors="infra@elastic.co" \
  name="${BEAT_NAME}" \
  vendor="${BEAT_VENDOR}" \
  version="${BEAT_VENDOR}" \
  release="1" \
  url="${BEAT_URL}" \
  summary="${BEAT_NAME}" \
  license="${BEAT_LICENSE}" \
  description="${BEAT_DESCRIPTION}"

#TODO remove once it's done
RUN ls -lah /usr/bin/tini

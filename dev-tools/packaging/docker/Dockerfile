# User/group args
ARG ELASTIC_AGENT_USER="elastic-agent"
ARG ELASTIC_AGENT_GROUP="elastic-agent"
ARG ELASTIC_AGENT_UID=1000
ARG ELASTIC_AGENT_GID=1000

# Capabilities
ARG LINUX_CAPABILITIES

# beats stuff
ARG BEAT_NAME="elastic-agent"
ARG BEAT_BINARY="elastic-agent"
ARG BEAT_HOME="/usr/share/${BEAT_NAME}/"
ARG HOST_BEAT_HOME="beat/"
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
ARG DOCKER_VARIANT="basic"

# Base images args

# Ubuntu
ARG UBUNTU_BASE_VERSION="24.04"

# Wolfi
ARG WOLFI_BASE_IMAGE="cgr.dev/chainguard/wolfi-base"
ARG WOLFI_BASE_VERSION="latest"


# Base images

## Ubuntu
FROM ubuntu:${UBUNTU_BASE_VERSION} AS elastic_agent_base_ubuntu

ARG ELASTIC_AGENT_USER
ARG ELASTIC_AGENT_GROUP
ARG ELASTIC_AGENT_UID
ARG ELASTIC_AGENT_GID

ENV BEAT_SETUID_AS=elastic-agent
# Delete the existing "ubuntu" user to prevent conflict with the user that is added later.
# See https://bugs.launchpad.net/cloud-images/+bug/2005129/comments/2.
RUN touch /var/mail/ubuntu && \
    chown ubuntu /var/mail/ubuntu && \
    userdel -r ubuntu && \
    apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes ca-certificates curl gawk xz-utils && \
    apt-get clean all && \
    groupadd --gid ${ELASTIC_AGENT_GID} ${ELASTIC_AGENT_GROUP} && \
    useradd -M --uid ${ELASTIC_AGENT_UID} --gid ${ELASTIC_AGENT_GID} --groups 0 ${ELASTIC_AGENT_USER}

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
ARG DOCKER_VARIANT
ARG ELASTIC_AGENT_USER
ARG ELASTIC_AGENT_GROUP
ARG ELASTIC_AGENT_UID
ARG ELASTIC_AGENT_GID

RUN addgroup -g ${ELASTIC_AGENT_GID} ${ELASTIC_AGENT_GROUP} && \
    adduser -H -D -u ${ELASTIC_AGENT_UID} -G ${ELASTIC_AGENT_GROUP} ${ELASTIC_AGENT_USER} && \
    apk update && \
    apk add --no-cache ca-certificates curl gawk shadow bash

# Extra set of dependencies for docker complete variant
RUN [ "${DOCKER_VARIANT}" != "complete" ] || ( apk update && \
            apk add --no-interactive --no-progress --no-cache nodejs-18=18.20.4-r0 npm=10.8.3-r0 glib dbus-glib libatk-1.0 \
            libatk-bridge-2.0 cups-libs libxcomposite libxdamage libxrandr libxkbcommon pango alsa-lib \
            font-opensans fontconfig gtk icu-data-full libnss mesa font-noto-cjk font-noto-emoji )

FROM elastic_agent_base_wolfi AS elastic_agent_base_wolfi_buildtools
RUN apk update && \
    apk add --no-cache libcap-utils

FROM elastic_agent_base_ubuntu AS elastic_agent_base_ubuntu_buildtools

RUN apt-get update -y  && apt-get install --no-install-recommends --yes libcap2-bin && apt-get clean all

# Elastic Agent files stage (collects files and fixes permissions
FROM elastic_agent_base_${BASE_IMAGE_FAMILY}_buildtools AS elastic_agent_files

# arguments redeclared here because https://docs.docker.com/reference/dockerfile/#understand-how-arg-and-from-interact
ARG HOST_BEAT_HOME
ARG BEAT_HOME
ARG BEAT_COMMIT_SHORT
ARG BEAT_BINARY

ARG ELASTIC_AGENT_UID
ARG ELASTIC_AGENT_GID
ARG LINUX_CAPABILITIES
ARG BASE_IMAGE_FAMILY

ARG DOCKER_VARIANT

COPY ${HOST_BEAT_HOME} ${BEAT_HOME}

RUN chmod 0777 ${BEAT_HOME}
RUN mkdir -p ${BEAT_HOME}/data ${BEAT_HOME}/data/elastic-agent-${BEAT_COMMIT_SHORT}/logs
RUN find ${BEAT_HOME} -type d -exec chmod 0755 {} \;
RUN find ${BEAT_HOME} -type f -exec chmod 0644 {} \;
RUN find ${BEAT_HOME}/data -type d -exec chmod 0777 {} \;
RUN find ${BEAT_HOME}/data -type f -exec chmod 0666 {} \;
RUN rm ${BEAT_HOME}/${BEAT_BINARY}
RUN ln -s ${BEAT_HOME}/data/elastic-agent-${BEAT_COMMIT_SHORT}/elastic-agent ${BEAT_HOME}/${BEAT_BINARY}
RUN chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/elastic-agent
RUN chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/*beat
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/osquery* || true)
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/apm-server || true)
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/endpoint-security || true)
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/fleet-server || true)
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/pf-elastic-collector || true)
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/pf-elastic-symbolizer || true)
RUN (chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/pf-host-agent || true)
RUN find ${BEAT_HOME}/data/elastic-agent-${BEAT_COMMIT_SHORT}/components -name "*.yml*" -type f -exec chmod 0644 {} \;

# TODO (Not sure if used)
#{{- range $i, $modulesd := .ModulesDirs }}
#    chmod 0775 {{ $beatHome}}/{{ $modulesd }} && \
#{{- end }}
#
# Extra files for specific variant builds

# Extra files for "cloud" variant
RUN [ "${DOCKER_VARIANT}" != "cloud" ] || ( \
    mkdir -p /opt/agentbeat /opt/filebeat /opt/metricbeat && \
    cp -f ${BEAT_HOME}/data/cloud_downloads/filebeat.sh /opt/filebeat/filebeat && \
    chmod +x /opt/filebeat/filebeat && \
    cp -f ${BEAT_HOME}/data/cloud_downloads/metricbeat.sh /opt/metricbeat/metricbeat && \
    chmod +x /opt/metricbeat/metricbeat && \
    tar xf ${BEAT_HOME}/data/cloud_downloads/agentbeat-*.tar.gz -C /opt/agentbeat --strip-components=1 && \
    rm -rf ${BEAT_HOME}/data/cloud_downloads \
    )

# Change ownership to the files
RUN chown -R ${ELASTIC_AGENT_UID}:${ELASTIC_AGENT_GID} ${BEAT_HOME}

# Keep this after any chown command, chown resets any applied capabilities
RUN setcap =p ${BEAT_HOME}/data/elastic-agent-${BEAT_COMMIT_SHORT}/elastic-agent && \
  ([ -z "${LINUX_CAPABILITIES}" ] || setcap ${LINUX_CAPABILITIES}  $(readlink -f ${BEAT_BINARY}))


# Elastic-agent images
FROM elastic_agent_base_${BASE_IMAGE_FAMILY} AS image_basic

# beats stuff (redeclared here because https://docs.docker.com/reference/dockerfile/#understand-how-arg-and-from-interact )
ARG BEAT_NAME
ARG BEAT_BINARY
ARG BEAT_HOME
ARG HOST_BEAT_HOME
ARG BEAT_VENDOR
ARG BEAT_VERSION
ARG BEAT_URL
ARG BEAT_DESCRIPTION
ARG BEAT_ROOT_IMPORT_PATH
ARG BEAT_COMMIT
ARG BEAT_COMMIT_SHORT
ARG BEAT_LICENSE
ARG BUILD_TIMESTAMP
ARG ELASTIC_AGENT_USER

COPY --from=elastic_agent_files ${BEAT_HOME} ${BEAT_HOME}
RUN mkdir /licenses && \
    cp /usr/share/elastic-agent/LICENSE.txt /licenses && \
    cp /usr/share/elastic-agent/NOTICE.txt /licenses

COPY --from=dockerbuild --chmod=0755 docker-entrypoint.elastic-agent /usr/local/bin/docker-entrypoint





USER ${ELASTIC_AGENT_USER}


ENV ELASTIC_CONTAINER="true"
ENV PATH=/usr/share/elastic-agent:$PATH
ENV GODEBUG="madvdontneed=1"

# When running under Docker, we must ensure libbeat monitoring pulls cgroup
# metrics from /sys/fs/cgroup/<subsystem>/, ignoring any paths found in
# /proc/self/cgroup.
ENV LIBBEAT_MONITORING_CGROUPS_HIERARCHY_OVERRIDE=/

WORKDIR ${BEAT_HOME}
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint"]

LABEL \
  org.label-schema.build-date="${BUILD_TIMESTAMP}" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.vendor="${BEAT_VENDOR}" \
  org.label-schema.license="${BEAT_LICENSE}" \
  org.label-schema.name="${BEAT_NAME}" \
  org.label-schema.version="${BEAT_VERSION}" \
  org.label-schema.url="${BEAT_URL}" \
  org.label-schema.vcs-url="${BEAT_ROOT_IMPORT_PATH}" \
  org.label-schema.vcs-ref="${BEAT_COMMIT}" \
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


FROM image_basic AS image_cloud

COPY --from=elastic_agent_files /opt /opt

# Generate folder for a stub command that will be overwritten at runtime
RUN mkdir /app && \
    chown {{ .user }}:{{ .user }} /app

FROM image_basic AS image_service

ARG BEAT_HOME

# TODO moving connectors.zip should probably be done in the elastic_agent_files stage
# and the extra python package should be done in the base image
RUN apk add --no-cache git make python-3.11 py3.11-pip && \
    unzip ${BEAT_HOME}/data/service/connectors-*.zip -d ${BEAT_HOME}/data/service && \
    mv ${BEAT_HOME}/data/service/elasticsearch_connectors-* /usr/share/connectors && \
    PYTHON=python3.11 make -C /usr/share/connectors clean install install-agent && \
    chmod 0755 ${BEAT_HOME}/data/elastic-agent-*/components/connectors

FROM image_basic AS image_complete

ARG BEAT_HOME
ARG ELASTIC_AGENT_GROUP
ARG ELASTIC_AGENT_USER


USER root
ENV NODE_PATH=${BEAT_HOME}/.node
RUN echo \
    $NODE_PATH \
    ${BEAT_HOME}/.config \
    ${BEAT_HOME}/.synthetics \
    ${BEAT_HOME}/.npm \
    ${BEAT_HOME}/.cache \
    | xargs -IDIR sh -c 'mkdir -p DIR && chmod 0775 DIR'

# Setup synthetics env vars
ENV ELASTIC_SYNTHETICS_CAPABLE=true
ENV ELASTIC_AGENT_COMPLETE=true
ENV TZ=UTC
ENV NODE_VERSION=18.20.4
ENV PATH="$NODE_PATH/node/bin:$PATH"
# Install the latest version of @elastic/synthetics forcefully ignoring the previously
# cached node_modules, heartbeat then calls the global executable to run test suites
# Setup node
RUN cd ${BEAT_HOME}/.node \
  && NODE_DOWNLOAD_URL="" \
  && case "$(arch)" in \
        arm64) \
           NODE_DOWNLOAD_URL=https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz \
           ;; \
       x86_64) \
           NODE_DOWNLOAD_URL=https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz \
           ;; \
       aarch64) \
           NODE_DOWNLOAD_URL=https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-arm64.tar.xz \
           ;; \
       *) \
           echo >&2 ; echo >&2 "Unsupported architecture \$(arch)" ; echo >&2 ; exit 1 ; \
           ;; \
     esac \
  && mkdir -p node \
  && curl ${NODE_DOWNLOAD_URL} | tar -xJ --strip 1 -C node \
  && chmod ugo+rwX -R $NODE_PATH \
# Install synthetics as a regular user, installing npm deps as root odesn't work
   # fix .node .npm and .synthetics
   && chown -R ${ELASTIC_AGENT_USER}:${ELASTIC_AGENT_GROUP} $NODE_PATH
USER {{ .user }}
# If this fails dump the NPM logs
RUN (npm i -g --loglevel verbose --production --engine-strict @elastic/synthetics@stack_release || sh -c 'tail -n +1 /root/.npm/_logs/* && exit 1') && \
    chmod ugo+rwX -R $NODE_PATH
USER root

# Install the deps as needed by the exact version of playwright elastic synthetics uses
# We don't use npx playwright install-deps because that could pull a newer version
# Install additional fonts as well
RUN apt-get update -y && \
    $NODE_PATH/node/lib/node_modules/@elastic/synthetics/node_modules/.bin/playwright install-deps chromium && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes \
    fonts-noto \
    fonts-noto-cjk

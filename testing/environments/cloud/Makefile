MAKEFILE_PATH:=$(abspath $(lastword ${MAKEFILE_LIST}))
MAKEFILE_DIR:=$(dir ${MAKEFILE_PATH})
REPO_ROOT:=$(abspath ${MAKEFILE_DIR}/../../../)
SNAPSHOT_SUFFIX:=-SNAPSHOT
ifeq (${SNAPSHOT}, false)
SNAPSHOT_SUFFIX:=""
endif
ifeq (${SNAPSHOT}, 0)
SNAPSHOT_SUFFIX:=""
endif
VERSION:=$(shell grep "const defaultBeatVersion =" ${REPO_ROOT}/version/version.go | cut -d\" -f2)${SNAPSHOT_SUFFIX}

export DOCKER_BUILDKIT=1

ELASTIC_AGENT_DOCKER_IMAGE=docker.elastic.co/cloud-release/elastic-agent-cloud
ELASTICSEARCH_DOCKER_IMAGE=docker.elastic.co/cloud-release/elasticsearch-cloud-ess
KIBANA_DOCKER_IMAGE=docker.elastic.co/cloud-release/kibana-cloud

CI_ELASTIC_AGENT_DOCKER_IMAGE=docker.elastic.co/observability-ci/elastic-agent
CI_KIBANA_DOCKER_IMAGE=docker.elastic.co/observability-ci/kibana

# Tag custom images with the username and current timestamp.
# The timestamp must be included to force images to be pulled.
USER_NAME?=${USER}
CUSTOM_IMAGE_TAG:=${VERSION}-${USER_NAME}-$(shell date +%s)

USER_ELASTIC_AGENT_DOCKER_IMAGE=docker.elastic.co/observability-ci/${USER_NAME}-elastic-agent
USER_KIBANA_DOCKER_IMAGE=docker.elastic.co/observability-ci/${USER_NAME}-kibana

.DEFAULT_GOAL := docker_image.auto.tfvars

##############################################################################
# Target for creating a .tfvars file, defining the custom Docker images to
# use in the deployment.
##############################################################################

docker_image.auto.tfvars: kibana_docker_image elastic_agent_docker_image
	@echo 'docker_image_override={"elasticsearch":"${ELASTICSEARCH_DOCKER_IMAGE}","kibana":"${CI_KIBANA_DOCKER_IMAGE}","agent":"${CI_ELASTIC_AGENT_DOCKER_IMAGE}"}' > $@
	@echo 'docker_image_tag_override={"elasticsearch":"${VERSION}","kibana":"${VERSION}","agent":"${CUSTOM_IMAGE_TAG}"}' >> $@

##############################################################################
# Terraform shortcut rules.
##############################################################################

.PHONY: apply
apply:
	@terraform apply -auto-approve


.PHONY: snap
snap:
	@echo ${VERSION}

.PHONY: destroy
destroy:
	@terraform destroy -auto-approve


.PHONY: deploy_local
deploy_local: build_elastic_agent_docker_image push_elastic_agent_docker_image
	@echo 'docker_image_override={"elasticsearch":"${ELASTICSEARCH_DOCKER_IMAGE}","kibana":"${KIBANA_DOCKER_IMAGE}","agent":"${CI_ELASTIC_AGENT_DOCKER_IMAGE}"}' > docker_image.auto.tfvars
	@echo 'docker_image_tag_override={"elasticsearch":"${VERSION}","kibana":"${VERSION}","agent":"${CUSTOM_IMAGE_TAG}"}' >> docker_image.auto.tfvars
	@terraform apply -auto-approve

##############################################################################
# Targets for building and pushing custom Kibana and Elastic Agent images.
##############################################################################

# kibana_docker_image builds the Cloud Kibana image.
# The image will be based off the
# stack version defined in ${REPO_ROOT}/.env, unless overridden.
.PHONY: build_kibana_docker_image
kibana_docker_image: build_kibana_docker_image
	docker push ${CI_KIBANA_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG}
build_kibana_docker_image:
	$(MAKE) -C ${REPO_ROOT} build-package
	docker build -t ${CI_KIBANA_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG} \
		-f "${REPO_ROOT}/testing/docker/kibana/Dockerfile-apmpackage" \
		--build-arg KIBANA_IMAGE=${KIBANA_DOCKER_IMAGE}:${IMAGE_TAG} \
		--platform linux/amd64 \
		"${REPO_ROOT}/build/packages"

# build_elastic_agent_docker_image builds the Cloud Elastic Agent image.
# The image will be based
# off the version defined in version.go,
# CUSTOM_IMAGE_TAG is appended to the version resulting in e.g:
# 8.7.0-SNAPSHOT-doe-1673961915
# unless overridden.
.PHONY: build_elastic_agent_docker_image
push_elastic_agent_docker_image: 
	cd ${REPO_ROOT}; CI_ELASTIC_AGENT_DOCKER_IMAGE=${CI_ELASTIC_AGENT_DOCKER_IMAGE} CUSTOM_IMAGE_TAG=${CUSTOM_IMAGE_TAG} mage cloud:push
build_elastic_agent_docker_image:
	cd ${REPO_ROOT}; DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 DOCKER_DEFAULT_PLATFORM=linux/amd64 mage cloud:image

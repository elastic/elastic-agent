STACK_VERSION ?= 8.6.1
AGENT_VERSION ?= 8.6.0
CLUSTER_DIGEST_FILE ?= cluster-digest.yml
CLUSTER_INFO_FILE ?= cluster-info.json
CLUSTER_NAME ?= e2e-elasic-agent-$(shell date +%s)
TEMPLATE_FILE ?= test-cluster.yml.tpl
SLACK_CHANNEL ?= @U0396725PSN
# The directory where the pre-downloaded agent binary is stored.
ARTIFACTS_DIR := e2e_artifacts

LOCAL_SSH_KEY ?= ~/.ssh/id_rsa

check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

.PHONY: clean
clean: 
	rm $(CURDIR)/$(CLUSTER_INFO_FILE)

.PHONY: set-arch
set-arch:
ifeq ($(filter $(shell uname -m),x86_64 amd64),$(shell uname -m))
	$(eval ARCH := x86_64)
	echo "x86_64"
else ifeq ($(filter $(shell uname -m),aarch64 arm64),$(shell uname -m))
	$(eval ARCH := arm64)	
endif

.PHONY: download-agent
download-agent: set-arch
	@$(call check_defined, AGENT_VERSION, AGENT_VERSION is not defined)
	mkdir -p $(ARTIFACTS_DIR)
	@echo "Downloading Elastic Agent..."
	curl -L "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$(AGENT_VERSION)-linux-$(ARCH).tar.gz" -o $(CURDIR)/$(ARTIFACTS_DIR)/elastic-agent.tar.gz
	tar -xzf $(CURDIR)/$(ARTIFACTS_DIR)/elastic-agent.tar.gz -C $(CURDIR)/$(ARTIFACTS_DIR)/

.PHONY: create-cluster
create-cluster:
	@$(call check_defined, SLACK_CHANNEL, SLACK_CHANNEL is not defined. Specify a slack channel to send notifications to.)
	@$(call check_defined, GITHUB_TOKEN, GITHUB_TOKEN is not defined. Specify a github token to use for the cluster.)
	oblt-cli cluster create custom --template-file $(CURDIR)/$(TEMPLATE_FILE) --output-file $(CURDIR)/$(CLUSTER_INFO_FILE) --parameters '{"StackVersion": "$(STACK_VERSION)", "ClusterName": "$(CLUSTER_NAME)", "SlackChannel": "$(SLACK_CHANNEL)"}' --wait 15
	sync $(CURDIR)/$(CLUSTER_INFO_FILE)
	oblt-cli cluster secrets digest-yml --cluster-name $$(cat $(CURDIR)/$(CLUSTER_INFO_FILE) | jq -r '.ClusterName') --output-file $(CURDIR)/$(CLUSTER_DIGEST_FILE)

.PHONY: run-tests
run-tests: set-arch
	@$(call check_defined, AGENT_VERSION, AGENT_VERSION is not defined)
	AGENT_VERSION=$(AGENT_VERSION) AGENT_BIN_PATH=$(CURDIR)/$(ARTIFACTS_DIR)/elastic-agent-$(AGENT_VERSION)-linux-$(ARCH)/elastic-agent go test -v -timeout 300s -tags=e2e github.com/elastic/elastic-agent/testing/e2e

.PHONY: destroy-cluster
destroy-cluster:	
	oblt-cli cluster destroy --force --cluster-name $$(jq -r '.ClusterName' $(CURDIR)/$(CLUSTER_INFO_FILE))

.PHONY: start-ubuntu
start-ubuntu:
	docker run --rm -ti --env-file e2e/infra/.env \
    -v $(LOCAL_SSH_KEY):/root/.ssh/id_rsa_libcloud \
    -v $(LOCAL_SSH_KEY).pub:/root/.ssh/id_rsa_libcloud.pub \
		-e SSH_KEY_PATH=/root/.ssh/id_rsa_libcloud \
    -v `pwd`:`pwd` \
    -w `pwd` gorambo/ogc:v4 \
    ogc e2e/infra/ubuntu.py up -v
	
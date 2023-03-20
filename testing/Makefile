STACK_VERSION ?= 8.6.1
CURRENT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CLUSTER_DIGEST_FILE := cluster-digest.yml
CLUSTER_INFO_FILE := cluster-info.json
CLUSTER_NAME := e2e-elasic-agent-$(shell date +%s)
SLACK_CHANNEL := @U0396725PSN

check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

.PHONY: clean
clean: 
	rm $(CURRENT_DIR)/cluster-info.json

.PHONY: create-cluster
create-cluster:
	@$(call check_defined, SLACK_CHANNEL, SLACK_CHANNEL is not defined. Specify a slack channel to send notifications to.)
	@$(call check_defined, GITHUB_TOKEN, GITHUB_TOKEN is not defined. Specify a github token to use for the cluster.)
	oblt-cli cluster create custom --template-file $(CURRENT_DIR)/test-cluster.yml.tpl --output-file $(CURRENT_DIR)/$(CLUSTER_INFO_FILE) --parameters '{"StackVersion": "$(STACK_VERSION)", "ClusterName": "$(CLUSTER_NAME)", "SlackChannel": "$(SLACK_CHANNEL)"}' --wait 15
	oblt-cli cluster secrets digest-yml --cluster-name $(shell cat $(CURRENT_DIR)/$(CLUSTER_INFO_FILE) | jq -r '.ClusterName') --output-file $(CURRENT_DIR)/$(CLUSTER_DIGEST_FILE)

.PHONY: run-tests
run-tests:
	AGENT_VERSION=8.6.0 ginkgo -- --config="$(CURRENT_DIR)/$(CLUSTER_DIGEST_FILE)"

.PHONY: destroy-cluster
destroy-cluster:	
	oblt-cli cluster destroy --force --cluster-name $(shell cat $(CURRENT_DIR)/cluster-info.json | jq -r '.ClusterName')
	
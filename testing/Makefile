STACK_VERSION ?= 8.6.1
CLUSTER_DIGEST_FILE ?= cluster-digest.yml
CLUSTER_INFO_FILE ?= cluster-info.json
CLUSTER_NAME ?= e2e-elasic-agent-$(shell date +%s)
TEMPLATE_FILE ?= test-cluster.yml.tpl
SLACK_CHANNEL ?= @U0396725PSN

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

.PHONY: create-cluster
create-cluster:
	@$(call check_defined, SLACK_CHANNEL, SLACK_CHANNEL is not defined. Specify a slack channel to send notifications to.)
	@$(call check_defined, GITHUB_TOKEN, GITHUB_TOKEN is not defined. Specify a github token to use for the cluster.)
	# oblt-cli cluster create custom --template-file $(CURDIR)/$(TEMPLATE_FILE) --output-file $(CURDIR)/$(CLUSTER_INFO_FILE) --parameters '{"StackVersion": "$(STACK_VERSION)", "ClusterName": "$(CLUSTER_NAME)", "SlackChannel": "$(SLACK_CHANNEL)"}' --wait 15
	oblt-cli cluster secrets digest-yml --cluster-name $(shell jq -r '.ClusterName' $(CLUSTER_INFO_FILE)) --output-file $(CURDIR)/$(CLUSTER_DIGEST_FILE)

.PHONY: run-tests
run-tests:
	AGENT_VERSION=8.6.0 go test -v -timeout 300s -tags=e2e -run ^TestElasticAgentUpgrade$ github.com/elastic/elastic-agent/testing/e2e

.PHONY: destroy-cluster
destroy-cluster:	
	oblt-cli cluster destroy --force --cluster-name $(shell jq -r '.ClusterName' $(CLUSTER_INFO_FILE))

.PHONY: start-ubuntu
start-ubuntu:
	docker run --rm -ti --env-file e2e/infra/.env \
    -v $(LOCAL_SSH_KEY):/root/.ssh/id_rsa_libcloud \
    -v $(LOCAL_SSH_KEY).pub:/root/.ssh/id_rsa_libcloud.pub \
		-e SSH_KEY_PATH=/root/.ssh/id_rsa_libcloud \
    -v `pwd`:`pwd` \
    -w `pwd` gorambo/ogc:v4 \
    ogc e2e/infra/ubuntu.py up -v
	
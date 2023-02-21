STACK_VERSION ?= 8.6.1
CURRENT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CLUSTER_DIGEST_FILE := cluster-digest.yml

.PHONY: clean
clean: 
	rm $(CURRENT_DIR)/cluster-info.json

.PHONY: create-cluster
create-cluster:
	echo $(STACK_VERSION)
	oblt-cli cluster create custom --template-file $(CURRENT_DIR)/test-cluster.yml.tpl --output-file $(CURRENT_DIR)/cluster-info.json --parameters '{"StackVersion": "$(STACK_VERSION)"}' --wait 15
	CLUSTER_NAME := $(shell cat $(CURRENT_DIR)/cluster-info.json | jq -r '.ClusterName')
	oblt-cli cluster secrets digest-yml --cluster-name $(CLUSTER_NAME) --output-file $(CURRENT_DIR)/$(CLUSTER_DIGEST_FILE)

.PHONY: run-tests
run-tests:
	ginkgo -- --config="$(CLUSTER_DIGEST_FILE)"

.PHONY: destroy-cluster
destroy-cluster:
	CLUSTER_NAME := $(shell cat $(CURRENT_DIR)/cluster-info.json | jq -r '.ClusterName')
	oblt-cli cluster destroy --force --cluster-name $(CLUSTER_NAME)
	
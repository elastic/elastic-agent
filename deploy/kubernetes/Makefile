ALL=elastic-agent-standalone elastic-agent-managed
BEAT_VERSION=$(shell head -n 1 ../../version/docs/version.asciidoc | cut -c 17- )

#variables needed for ci-create-kubernetes-templates-pull-request
ELASTIC_AGENT_REPO=./
ELASTIC_AGENT_REPO_PATH=$(ELASTIC_AGENT_REPO)
ELASTIC_AGENT_BRANCH=update-k8s-templates-$(shell date "+%Y%m%d%H%M%S")

.PHONY: generate-k8s $(ALL)
generate-k8s: $(ALL)
	
test: generate-k8s
	for FILE in $(shell ls *-kubernetes.yaml); do \
		BEAT=$$(echo $$FILE | cut -d \- -f 1); \
		kubectl create -f $$FILE; \
	done

clean:
	@for f in $(ALL); do rm -f "$$f-kubernetes.yaml"; done

$(ALL): 
ifdef WITHOUTCONFIG
	@echo "Generating $@-kubernetes-without-configmap.yaml"
	@rm -f $@-kubernetes-without-configmap.yaml
	@for f in $(shell ls $@/*.yaml | grep -v configmap); do \
		sed "s/%VERSION%/${BEAT_VERSION}/g" $$f >> $@-kubernetes-without-configmap.yaml; \
		echo --- >> $@-kubernetes-without-configmap.yaml; \
	done
else
	@echo "Generating $@-kubernetes.yaml" 
	@rm -f $@-kubernetes.yaml 
	@for f in $(shell ls $@/*.yaml); do \
		sed "s/%VERSION%/${BEAT_VERSION}/g" $$f >> $@-kubernetes.yaml; \
		echo --- >> $@-kubernetes.yaml; \
	done 
endif


## ci-create-kubernetes-templates-pull-request : Create the pull request for the kubernetes templates
.PHONY: ci-create-kubernetes-templates-pull-request
ci-create-kubernetes-templates-pull-request:
	cd $(ELASTIC_AGENT_REPO_PATH)
	echo "INFO: create branch"
	git checkout -b $(ELASTIC_AGENT_BRANCH)
	echo "INFO: add files if any"
	git add .
	echo "INFO: commit changes if any"
	git diff --staged --quiet || git commit -m "[automation] Publish kubernetes templates for elastic-agent"
	echo "INFO: show remote details"
	git remote -v
ifeq ($(DRY_RUN),TRUE)
		echo "INFO: skip pushing branch"
else
		echo "INFO: push branch"
		git push --set-upstream origin $(ELASTIC_AGENT_BRANCH)
		echo "INFO: create pull request"
		gh pr create \
			--title "Update kubernetes templates for elastic-agent [templates.d]" \
			--body "Automated by ${BUILD_URL}" \
			--label automation \
			--base main \
			--head $(ELASTIC_AGENT_BRANCH) \
			--reviewer elastic/obs-cloudnative-monitoring
endif 
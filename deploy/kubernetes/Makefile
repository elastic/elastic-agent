SHELL := /bin/bash

ALL=elastic-agent-standalone elastic-agent-managed
WORKSPACE=$(shell git rev-parse --show-toplevel)
BEAT_VERSION=$(shell grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\-[a-zA-Z]+[0-9]+)?' "${WORKSPACE}/version/version.go")
BRANCH_VERSION=$(shell cut -d. -f1-2 <<< '${BEAT_VERSION}')

#variables needed for ci-create-kubernetes-templates-pull-request
ELASTIC_AGENT_REPO=kibana
ELASTIC_AGENT_REPO_PATH=x-pack/plugins/fleet/server/services/
FILE_REPO=elastic_agent_manifest.ts
ELASTIC_AGENT_BRANCH=update-k8s-templates-$(shell date "+%Y%m%d%H%M%S")

#variable needed for kustomize build
KUSTOMIZE=elastic-agent-kustomize
KUSTOMIZE_DEFAULT=elastic-agent-kustomize/default
KUSTOMIZE_KSM_AUTOSHARDING=elastic-agent-kustomize/ksm-autosharding
KUSTOMIZE_KSM_HINTS=elastic-agent-kustomize/ksm-hints

# variable for processor for elastic-agent-standalone
define ELASTIC_PROCESSOR
processors:\n            - add_fields:\n                fields:\n                  onboarding_id: '%ONBOARDING_ID%'
endef

.PHONY: generate-k8s $(ALL)
generate-k8s: $(ALL)

test: generate-k8s
	for FILE in $(shell ls *-kubernetes.yaml | grep -v elastic-agent-standalone-ksm); do \
		BEAT=$$(echo $$FILE | cut -d \- -f 1); \
		kubectl create -f $$FILE; \
	done

clean:
	@for f in $(ALL); do rm -f "$$f-kubernetes.yaml"; done

$(ALL):
ifdef WITHOUTCONFIG
	@echo "Generating $@-kubernetes-without-configmap.yaml"
	@rm -f $@-kubernetes-without-configmap.yaml
	@for f in $(shell ls $@/*.yaml | grep -v configmap ); do \
		sed -e "s/%VERSION%/VERSION/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" $$f >> $@-kubernetes-without-configmap.yaml; \
		echo --- >> $@-kubernetes-without-configmap.yaml; \
	done
else
	@echo "Generating $@-kubernetes.yaml"
	@rm -f $@-kubernetes.yaml
	@for f in $(shell ls $@/*.yaml | grep -v elastic-agent-standalone-ksm); do \
		sed -e "s/%VERSION%/${BEAT_VERSION}/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" $$f >> $@-kubernetes.yaml; \
		echo --- >> $@-kubernetes.yaml; \
	done
endif

CHDIR_SHELL := $(SHELL)
define chdir
   $(eval _D=$(firstword $(1) $(@D)))
   $(info $(MAKE): cd $(_D)) $(eval SHELL = cd $(_D); $(CHDIR_SHELL))
endef

## ci-clone-kibana-repository : Clone Kibana Repository and copy new files for the PR
.PHONY: ci-clone-kibana-repository
ci-clone-kibana-repository:
	git clone https://github.com/elastic/kibana.git
	cp $(FILE_REPO)  $(ELASTIC_AGENT_REPO)/$(ELASTIC_AGENT_REPO_PATH)

## ci-create-kubernetes-templates-pull-request : Create the pull request for the kubernetes templates
$(eval HASDIFF =$(shell sh -c "git status | grep $(FILE_REPO) | wc -l"))
.PHONY: ci-create-kubernetes-templates-pull-request
ci-create-kubernetes-templates-pull-request:
ifeq ($(HASDIFF),1)
	echo "INFO: Create branch to update k8s templates"	
	@git config user.name "${GITHUB_USERNAME_SECRET}"
	@git config user.email "${GITHUB_EMAIL_SECRET}"
	@git config remote.origin.url "https://${GITHUB_USERNAME_SECRET}:${GITHUB_TOKEN_SECRET}@github.com/elastic/kibana.git"
	git checkout -b $(ELASTIC_AGENT_BRANCH)
	echo "INFO: add files if any"
	git add $(ELASTIC_AGENT_REPO_PATH)$(FILE_REPO)
	echo "INFO: commit changes if any"
	git diff --staged --quiet || git commit -m "[Automated PR] Publish kubernetes templates for elastic-agent"
	echo "INFO: show remote details"
	git remote -v

ifeq ($(DRY_RUN),TRUE)
	echo "INFO: skip pushing branch"
else
	echo "INFO: push branch"
	@git push --set-upstream origin $(ELASTIC_AGENT_BRANCH)
	echo "INFO: create pull request"
	@GITHUB_TOKEN=$(GITHUB_TOKEN_SECRET) gh pr create \
		--title "Update kubernetes templates for elastic-agent" \
		--body "Automated by ${BUILDKITE_BUILD_URL}" \
		--label automation \
		--label release_note:skip \
		--label backport:skip \
		--base main \
		--head $(ELASTIC_AGENT_BRANCH)
endif

else
	echo "No differences found with kibana git repository"
endif


## ci-create-kustomize : Create default kustomize folder 
.PHONY: ci-create-kustomize $(ALL)
ci-create-kustomize: $(ALL)

ifdef GENERATEKUSTOMIZE
export ELASTIC_PROCESSOR
$(ALL):
	@echo "Generating $@ kustomize-default files"
	@for f in $(shell ls $@/*.yaml | grep -v elastic-agent-standalone-daemonset-configmap); do \
		cp -r $$f  $(KUSTOMIZE_DEFAULT)/$@/base; \
	done

	sed -e "s/%VERSION%/${BEAT_VERSION}/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" $@/$@-daemonset.yaml > $(KUSTOMIZE_DEFAULT)/$@/base/$@-daemonset.yaml

	@echo "Generating $@ kustomize-ksm-autosharding files"
	@for f in $(shell ls $@/*.yaml | grep -v elastic-agent-standalone-daemonset-configmap); do \
		cp -r $$f  $(KUSTOMIZE_KSM_AUTOSHARDING)/$@/base; \
	done
	
	@echo "Generating $@ kustomize-ksm-hints files"
	@for f in $(shell ls elastic-agent-standalone/*.yaml | grep elastic-agent-standalone-daemonset-configmap.yaml); do \
		cp -r $$f  $(KUSTOMIZE_KSM_HINTS)/elastic-agent-standalone; \
	done
	sed -i.bak -e "s/#hints.enabled/hints.enabled/g" -e "s/#hints.default_container_logs/hints.default_container_logs/g" $(KUSTOMIZE_KSM_HINTS)/elastic-agent-standalone/elastic-agent-standalone-daemonset-configmap.yaml
	sed -i.bak -e "/- id: container-log/,/- \/var\/log\/containers/d" $(KUSTOMIZE_KSM_HINTS)/elastic-agent-standalone/elastic-agent-standalone-daemonset-configmap.yaml
	rm $(KUSTOMIZE_KSM_HINTS)/elastic-agent-standalone/elastic-agent-standalone-daemonset-configmap.yaml.bak 
	sed -e "s/%VERSION%/${BEAT_VERSION}/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g"  $(KUSTOMIZE_KSM_HINTS)/elastic-agent-standalone/kustomization.yaml.original > $(KUSTOMIZE_KSM_HINTS)/elastic-agent-standalone/kustomization.yaml

	mkdir -p $(KUSTOMIZE_KSM_AUTOSHARDING)/$@/extra/
	sed -e "s/%VERSION%/${BEAT_VERSION}/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" -e "/name: elastic-agent-state/,+1 s/^/#/" -e "/path: \/var\/lib\/$@\/kube-system\/state/,+1 s/^/#/" $@/$@-daemonset.yaml > $(KUSTOMIZE_KSM_AUTOSHARDING)/$@/base/$@-daemonset.yaml
	sed -e "s/%VERSION%/${BEAT_VERSION}/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" -e "/name: elastic-agent-state/,+1 s/^/#/" -e "/path: \/var\/lib\/$@\/kube-system\/state/,+1 s/^/#/" $@/$@-daemonset.yaml > $(KUSTOMIZE_KSM_AUTOSHARDING)/$@/base/$@-daemonset.yaml

	sed -e "s/%VERSION%/${BEAT_VERSION}/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" -e "s/hostNetwork: true/hostNetwork: false/g" -e "s/DaemonSet/StatefulSet/g" -e "s/agent-node-datastreams/agent-ksm-datastreams/g" -e "/name: elastic-agent-state/,+1 s/^/#/" -e "/path: \/var\/lib\/$@\/kube-system\/state/,+1 s/^/#/" $@/$@-daemonset.yaml > $(KUSTOMIZE_KSM_AUTOSHARDING)/$@/extra/$@-statefulset.yaml

	@echo "Generating processor $$ELASTIC_PROCESSOR"
	sed -e "s/#<processors_placeholder>/$$ELASTIC_PROCESSOR/g"  elastic-agent-standalone/elastic-agent-standalone-daemonset-configmap.yaml > $(KUSTOMIZE_DEFAULT)/elastic-agent-standalone/base/elastic-agent-standalone-daemonset-configmap.yaml
	
else
	echo "No KSM templates generated. Please run: GENERATEKUSTOMIZE=true make ci-create-kustomize "
endif

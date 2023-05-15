ALL=elastic-agent-standalone elastic-agent-managed
BEAT_VERSION=$(shell grep '^:stack-version:' ../../version/docs/version.asciidoc | cut -c 17- )
BRANCH_VERSION=$(shell grep '^:doc-branch:' ../../version/docs/version.asciidoc | cut -c 14- )

#variables needed for ci-create-kubernetes-templates-pull-request
ELASTIC_AGENT_REPO=kibana
ELASTIC_AGENT_REPO_PATH=x-pack/plugins/fleet/server/services/
FILE_REPO=elastic_agent_manifest.ts
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
	@for f in $(shell ls $@/*.yaml | grep -v daemonset-configmap); do \
		sed -e "s/%VERSION%/VERSION/g" -e "s/%BRANCH%/${BRANCH_VERSION}/g" $$f >> $@-kubernetes-without-configmap.yaml; \
		echo --- >> $@-kubernetes-without-configmap.yaml; \
	done
else
	@echo "Generating $@-kubernetes.yaml"
	@rm -f $@-kubernetes.yaml
	@for f in $(shell ls $@/*.yaml); do \
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
	git clone git@github.com:elastic/kibana.git
	cp $(FILE_REPO)  $(ELASTIC_AGENT_REPO)/$(ELASTIC_AGENT_REPO_PATH)

## ci-create-kubernetes-templates-pull-request : Create the pull request for the kubernetes templates
$(eval HASDIFF =$(shell sh -c "git status | grep $(FILE_REPO) | wc -l"))
.PHONY: ci-create-kubernetes-templates-pull-request
ci-create-kubernetes-templates-pull-request:
ifeq ($(HASDIFF),1)
	echo "INFO: Create branch to update k8s templates"
	git config user.name obscloudnativemonitoring
	git config user.email obs-cloudnative-monitoring@elastic.co
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
	@gh pr create \
		--title "Update kubernetes templates for elastic-agent" \
		--body "Automated by ${BUILD_URL}" \
		--label automation \
		--label release_note:skip \
		--base main \
		--head $(ELASTIC_AGENT_BRANCH) \
		--reviewer elastic/obs-cloudnative-monitoring
endif

else
	echo "No differences found with kibana git repository"
endif


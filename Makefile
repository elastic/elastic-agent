BUILD_DIR=$(CURDIR)/build
COVERAGE_DIR=$(BUILD_DIR)/coverage
BEATS?=elastic-agent
PROJECTS= $(BEATS)
PYTHON_ENV?=$(BUILD_DIR)/python-env
MAGE_VERSION     ?= v1.13.0
MAGE_PRESENT     := $(shell mage --version 2> /dev/null | grep $(MAGE_VERSION))
MAGE_IMPORT_PATH ?= github.com/magefile/mage
NOTICE_TEMPLATE  ?= NOTICE.txt.tmpl
NOTICE_FILE      ?= NOTICE.txt
ELASTIC_AGENT_VERSION=$(shell grep defaultBeatVersion version/version.go | cut -d'=' -f2 | tr -d '" ')

export MAGE_IMPORT_PATH

## mage : Sets mage
.PHONY: mage
mage:
ifndef MAGE_PRESENT
	@echo Installing mage $(MAGE_VERSION).
	@go install ${MAGE_IMPORT_PATH}@$(MAGE_VERSION)
	@-mage -clean
endif
	@true


## help : Show this help.
help: Makefile
	@printf "Usage: make [target] [VARIABLE=value]\nTargets:\n"
	@sed -n 's/^## //p' $< | awk 'BEGIN {FS = ":"}; { if(NF>1 && $$2!="") printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 ; else printf "%40s\n", $$1};'
	@printf "Variables:\n"
	@grep -E "^[A-Za-z0-9_]*\?=" $< | awk 'BEGIN {FS = "\\?="}; { printf "  \033[36m%-25s\033[0m  Default values: %s\n", $$1, $$2}'

## notice : Generates the NOTICE file.
.PHONY: notice
notice:
	@echo "Generating NOTICE"
	go mod tidy
	go mod download
	go list -m -json all | go run go.elastic.co/go-licence-detector \
		-includeIndirect \
		-rules dev-tools/notice/rules.json \
		-overrides dev-tools/notice/overrides.json \
		-noticeTemplate dev-tools/notice/$(NOTICE_TEMPLATE) \
		-noticeOut $(NOTICE_FILE) \
		-depsOut ""
	cat dev-tools/notice/NOTICE.txt.append >> NOTICE.txt

## check-ci: Run all the checks under the ci, this doesn't include the linter which is run via a github action.
.PHONY: check-ci
check-ci:
	@mage update
	@$(MAKE) notice
	@$(MAKE) -C deploy/kubernetes generate-k8s
	@$(MAKE) check-no-changes

## check: run all the checks including linting using golangci-lint.
.PHONY: check
check:
	@$(MAKE) check-ci
	@$(MAKE) check-go

## check-go: download and run the go linter.
.PHONY: check-go
check-go: ## - Run golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.44.2
	@./bin/golangci-lint run -v

## check-no-changes : Check there is no local changes.
.PHONY: check-no-changes
check-no-changes:
	@go mod tidy
	@git diff | cat
	@git update-index --refresh
	@git diff-index --exit-code HEAD --

## get-version : Get the Elastic Agent Version
.PHONY: get-version
get-version:
	@echo $(ELASTIC_AGENT_VERSION)

## release-manager-dependencies : Prepares the dependencies file
.PHONY: release-manager-dependencies
release-manager-dependencies:
	@mkdir -p build/distributions
	@$(MAKE) NOTICE_TEMPLATE=dependencies.csv.tmpl NOTICE_FILE=build/distributions/dependencies.csv notice
	@cd build/distributions && shasum -a 512 dependencies.csv > dependencies.csv.sha512

.PHONY: release-manager-dependencies-snapshot
release-manager-dependencies-snapshot: ## - Prepares the dependencies file for a snapshot.
	@$(MAKE) SNAPSHOT=true release-manager-dependencies

.PHONY: release-manager-dependencies-release
release-manager-dependencies-release: ## - Prepares the dependencies file for a release.
	@$(MAKE) release-manager-dependencies

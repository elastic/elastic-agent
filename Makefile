BUILD_DIR=$(CURDIR)/build
COVERAGE_DIR=$(BUILD_DIR)/coverage
BEATS?=elastic-agent
PROJECTS= $(BEATS)
PYTHON_ENV?=$(BUILD_DIR)/python-env
GOLANGCI_LINT_VERSION := v$(shell awk '/^golangci-lint / {print $$2}' .tool-versions)

## mage : Sets mage
.PHONY: mage
mage:
	@echo Installing mage
	@go install github.com/magefile/mage
	@-mage -clean


## install-gotestsum : Install gotestsum
.PHONY: install-gotestsum
install-gotestsum:
	@echo Installing gotestsum
	go install gotest.tools/gotestsum
	@-gotestsum --version

## install-golangci-lint : Install golangci-lint
.PHONY: install-golangci-lint
install-golangci-lint:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s $(GOLANGCI_LINT_VERSION)

## help : Show this help.
help: Makefile
	@printf "Usage: make [target] [VARIABLE=value]\nTargets:\n"
	@sed -n 's/^## //p' $< | awk 'BEGIN {FS = ":"}; { if(NF>1 && $$2!="") printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 ; else printf "%40s\n", $$1};'
	@printf "Variables:\n"
	@grep -E "^[A-Za-z0-9_]*\?=" $< | awk 'BEGIN {FS = "\\?="}; { printf "  \033[36m%-25s\033[0m  Default values: %s\n", $$1, $$2}'

## notice : Generates the NOTICE.txt and NOTICE-fips.txt files.
.PHONY: notice
notice:
	@mage notice

## check-ci: Run all the checks under the ci, this doesn't include the linter which is run via a github action.
.PHONY: check-ci
check-ci:
	@mage -v check
	@$(MAKE) notice
	@GENERATEKUSTOMIZE=true $(MAKE) -C deploy/kubernetes generate-k8s
	@$(MAKE) -C deploy/kubernetes generate-k8s
	@mage -v helm:lint
	@mage -v helm:updateAgentVersion
	@mage -v helm:renderExamples
	@mage -v integration:buildKubernetesTestData
	@$(MAKE) check-no-changes

## check: run all the checks including linting using golangci-lint.
.PHONY: check
check:
	@$(MAKE) check-ci
	@$(MAKE) check-go

## check-go: download and run the go linter.
.PHONY: check-go
check-go: lint

## lint: download and run the go linter on current changes.
.PHONY: lint
lint: install-golangci-lint
	@./bin/golangci-lint run -v --timeout=30m --whole-files --new

## lint-all: download and run the go linter on the whole codebase.
.PHONY: lint-all
lint-all: install-golangci-lint
	@./bin/golangci-lint run -v --timeout=30m

## check-no-changes : Check there is no local changes.
.PHONY: check-no-changes
check-no-changes:
	@go mod tidy
	@git diff | cat
	@git update-index --refresh
	@git diff-index --exit-code HEAD --

## get-version : Get the libbeat version
.PHONY: get-version
get-version:
	@mage dumpVariables | grep 'beat_version' | cut -d"=" -f 2 | tr -d " "

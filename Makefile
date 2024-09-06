BUILD_DIR=$(CURDIR)/build
COVERAGE_DIR=$(BUILD_DIR)/coverage
BEATS?=elastic-agent
PROJECTS= $(BEATS)
PYTHON_ENV?=$(BUILD_DIR)/python-env
MAGE_PRESENT     := $(shell mage --version 2> /dev/null | grep $(MAGE_VERSION))
MAGE_IMPORT_PATH ?= github.com/magefile/mage
export MAGE_IMPORT_PATH

## mage : Sets mage
.PHONY: mage
mage:
ifndef MAGE_PRESENT
	@echo Installing mage.
	@go install ${MAGE_IMPORT_PATH}
	@-mage -clean
else
	@echo Mage already installed.
endif

## help : Show this help.
help: Makefile
	@printf "Usage: make [target] [VARIABLE=value]\nTargets:\n"
	@sed -n 's/^## //p' $< | awk 'BEGIN {FS = ":"}; { if(NF>1 && $$2!="") printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 ; else printf "%40s\n", $$1};'
	@printf "Variables:\n"
	@grep -E "^[A-Za-z0-9_]*\?=" $< | awk 'BEGIN {FS = "\\?="}; { printf "  \033[36m%-25s\033[0m  Default values: %s\n", $$1, $$2}'

## notice : Generates the NOTICE file.
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
	@$(MAKE) check-no-changes

## check: run all the checks including linting using golangci-lint.
.PHONY: check
check:
	@$(MAKE) check-ci
	@$(MAKE) check-go

## check-go: download and run the go linter.
.PHONY: check-go
check-go: ## - Run golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.55.2
	@./bin/golangci-lint run -v

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

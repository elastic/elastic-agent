BUILD_DIR=$(CURDIR)/build
COVERAGE_DIR=$(BUILD_DIR)/coverage
BEATS?=elastic-agent
PROJECTS= $(BEATS)
PYTHON_ENV?=$(BUILD_DIR)/python-env
PYTHON_EXE?=python3
PYTHON_ENV_EXE=${PYTHON_ENV}/bin/$(notdir ${PYTHON_EXE})
VENV_PARAMS?=
FIND=find . -type f -not -path "*/build/*" -not -path "*/.git/*"
GOLINT=golint
GOLINT_REPO=golang.org/x/lint/golint
XPACK_SUFFIX=''
MAGE_VERSION     ?= v1.11.0
MAGE_PRESENT     := $(shell mage --version 2> /dev/null | grep $(MAGE_VERSION))
MAGE_IMPORT_PATH ?= github.com/magefile/mage
export MAGE_IMPORT_PATH

## mage : Sets mage
.PHONY: mage
mage:
ifndef MAGE_PRESENT
	@echo Installing mage $(MAGE_VERSION).
	@go get -ldflags="-X $(MAGE_IMPORT_PATH)/mage.gitTag=$(MAGE_VERSION)" ${MAGE_IMPORT_PATH}@$(MAGE_VERSION)
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
		-noticeTemplate dev-tools/notice/NOTICE.txt.tmpl \
		-noticeOut NOTICE.txt \
		-depsOut ""

## check-no-changes : Check there is no local changes.
.PHONY: check-no-changes
check-no-changes:
	@go mod tidy
	@git diff | cat
	@git update-index --refresh
	@git diff-index --exit-code HEAD --

### Packaging targets ####

## snapshot : Builds a snapshot release.
.PHONY: snapshot
snapshot:
	@$(MAKE) SNAPSHOT=true release

## release : Builds a release.
.PHONY: release
release:
	@mage dumpVariables
	@$(foreach var,$(BEATS) ,$(MAKE) -C $(var) release || exit 1;)
	@$(foreach var,$(BEATS), \
      test -d $(var)/build/distributions && test -n "$$(ls $(var)/build/distributions)" || exit 0; \
      mkdir -p build/distributions/$(subst $(XPACK_SUFFIX),'',$(var)) && mv -f $(var)/build/distributions/* build/distributions/$(subst $(XPACK_SUFFIX),'',$(var))/ || exit 1;)

## release-manager-snapshot : Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
.PHONY: release-manager-snapshot
release-manager-snapshot:
	@$(MAKE) SNAPSHOT=true release-manager-release

## release-manager-release : Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
.PHONY: release-manager-release
release-manager-release:
	GO_VERSION=$(shell cat ./.go-version) ./dev-tools/run_with_go_ver $(MAKE) release

## get-version : Get the libbeat version
.PHONY: get-version
get-version:
	@mage dumpVariables | grep 'beat_version' | cut -d"=" -f 2 | tr -d " "

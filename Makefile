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

## release-manager-snapshot : Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
.PHONY: release-manager-snapshot
release-manager-snapshot:
	@$(MAKE) SNAPSHOT=true release-manager-release

## release-manager-release : Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
.PHONY: release-manager-release
release-manager-release:
	GO_VERSION=$(shell cat ./.go-version) ./dev-tools/run_with_go_ver $(MAKE) release


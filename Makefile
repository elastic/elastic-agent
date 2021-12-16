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

## check-python : Python Linting.
.PHONY: check-python
check-python: python-env
	@. $(PYTHON_ENV)/bin/activate; \
	$(FIND) -name *.py -name *.py -not -path "*/build/*" -exec $(PYTHON_ENV)/bin/autopep8 -d --max-line-length 120  {} \; | (! grep . -q) || (echo "Code differs from autopep8's style" && false); \
	$(FIND) -name *.py -not -path "*/build/*" | xargs $(PYTHON_ENV)/bin/pylint --py3k -E || (echo "Code is not compatible with Python 3" && false)

## docs : Builds the documents for each beat
.PHONY: docs
docs:
	@$(foreach var,$(PROJECTS),BUILD_DIR=${BUILD_DIR} $(MAKE) -C $(var) docs || exit 1;)
	sh ./script/build_docs.sh dev-guide github.com/elastic/beats/docs/devguide ${BUILD_DIR}

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

## python-env : Sets up the virtual python environment.
.PHONY: python-env
python-env:
	@test -d $(PYTHON_ENV) || ${PYTHON_EXE} -m venv $(VENV_PARAMS) $(PYTHON_ENV)
	@. $(PYTHON_ENV)/bin/activate; \
	${PYTHON_EXE} -m pip install -q --upgrade pip autopep8==1.5.4 pylint==2.4.4; \
	find $(PYTHON_ENV) -type d -name dist-packages -exec sh -c "echo dist-packages > {}.pth" ';'
	@# Work around pip bug. See: https://github.com/pypa/pip/issues/4464

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


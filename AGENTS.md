# AGENTS.md

Guidance for humans and automated coding agents working in this repository.

## What is Elastic Agent

Elastic Agent is a unified daemon that collects data from the OS, cloud, containers, and integrations. It runs in **standalone** mode (local YAML policy) or **managed** mode (policy from Fleet Server), supervises **components** as child processes, and ships telemetry to configured outputs (for example Elasticsearch). For a deeper walkthrough, see [docs/architecture.md](./docs/architecture.md).

## Build tool: Mage

Use **[mage](https://magefile.org/)** as the primary build and task runner. Install it with:

```bash
go install github.com/magefile/mage@latest
```

Discover targets and flags:

```bash
mage -l            # List targets
mage -h <Target>   # Help for a target (when doc strings are present)
```

Run tasks as `mage <namespace>:<target>` or `mage <target>` when documented (for example `mage notice`). Docstrings in [magefile.go](./magefile.go) describe targets and environment variables.

A **Makefile** still exists and CI runs targets such as `make check-ci` and `make lint`. Prefer mage for local development, but run CI-oriented Makefile targets before opening a PR when practical.

### Common commands

```bash
mage build:binary   # Main agent binary
mage build:all      # All binaries for current platform
mage dev:build      # DEV build (debug symbols)
mage test:unit      # All unit tests
mage fmt            # Format .go and .py files
mage check:all      # License headers, integration-test define checks, docs file validation
mage check:lint     # golangci-lint on changed files (see make lint)
mage check:lintAll  # golangci-lint on entire codebase (see make lint-all)
mage update         # Regenerate control protocol, configs, specs
mage tidy           # go mod tidy recursively across repo modules
mage clean          # Clean build artifacts
```

Integration tests and packaging often need Docker and extra env vars; see [magefile.go](./magefile.go) and [docs/test-framework-dev-guide.md](./docs/test-framework-dev-guide.md).

## Prerequisites

- Go version in [.go-version](./.go-version)
- Docker (packaging and integration tests)
- Git submodules: `git submodule update --init`
- One-time environment setup: `mage prepare:env`

## Repository structure (overview)

High-level areas:

| Path | Purpose |
|------|---------|
| `internal/pkg/agent/application/` | Core agent logic: coordinator, config managers, upgrade, monitoring |
| `internal/pkg/agent/cmd/` | CLI commands (run, install, enroll, upgrade, status) |
| `internal/pkg/agent/transpiler/` | Policy AST and variable substitution |
| `internal/pkg/composable/` | Dynamic variable providers |
| `internal/pkg/agent/fleetapi/` | Fleet Server HTTP client and action handling |
| `pkg/component/` | Component model, spec loading, platform detection |
| `pkg/component/runtime/` | CommandRuntime (subprocess) and ServiceRuntime (OS service) |
| `pkg/control/v2/` | gRPC control protocol definitions (generated sources under `cproto/`) |
| `specs/` | Component `.spec.yml` files defining supported inputs/outputs |
| `deploy/helm/` | Helm charts (for example elastic-agent and EDOT collector stacks) |
| `dev-tools/` | Developer tooling for build, packaging, notice generation, mage targets |
| `testing/` | Testing utiliteis including integration test definitions |
| `docs/` | Architecture and developer guides |
| `changelog/` | Changelog fragments for releases |
| `build/` | Produced build and testing artifacts |

Entry flow: `main.go` → `cmd.NewCommand()` → Cobra command tree → `application.New()` initializes platform specs, config managers, and the coordinator.

### `beats/` is a git submodule — do not modify for agent changes

The **`beats/`** directory is a **git submodule** (see `.gitmodules`: `elastic/beats`). The main module **replaces** `github.com/elastic/beats/v7` with `./beats` in `go.mod`.

**Do not edit files under `beats/` when implementing changes to the Elastic Agent codebase.** Agent work belongs in this repo’s own packages (for example `internal/`, `pkg/`, `specs/`). Submodule bumps are a separate, intentional maintenance step — not part of routine feature or bugfix work.

## Deployment architecture

Refer to [architecture.md](./docs/architecture.md).

## Packaging and delivery

Build artifacts (for example tar, deb, rpm, Docker images) are produced via mage packaging targets; see `magefile.go` for environment variables such as `EXTERNAL`, `SNAPSHOT`, `PLATFORMS`, `PACKAGES`, `DEV`, `DOCKER_VARIANTS`. Kubernetes-oriented deployment material lives under `deploy/helm/`.
Produced artifacts will be placed in the `build` directory.

## Testing

```bash
mage test:unit        # All unit tests (typical pre-PR gate)
mage test:coverage    # Unit tests with coverage report
go test -run TestName ./path/to/pkg -v   # Single test / package
```

Treat **`mage test:unit` passing** as the minimum bar before considering a change complete. If you add or change integration/E2E behavior, run the relevant mage integration targets and consult the testing docs.

Testing artifacts, including outputs and results will be placed in the `build/` directory.

### Integration Tests

See [docs/test-framework-dev-guide.md](./docs/test-framework-dev-guide.md).

## Dependencies (not exhaustive)

Major **direct** dependencies agents often interact with (see [go.mod](./go.mod) for the full graph):

- **`github.com/elastic/beats/v7`** — Beat libraries (vendored via **`beats/` submodule**; do not edit submodule for agent-only changes)
- **`github.com/elastic/elastic-agent-client/v7`** — agent ↔ component gRPC client protocol
- **`github.com/elastic/go-elasticsearch/v8`** — Elasticsearch client
- **`github.com/spf13/cobra`** — CLI
- **`github.com/rs/zerolog`** — structured logging
- **`go.elastic.co/apm/v2`** — APM tracing
- **OpenTelemetry Collector Contrib** packages — EDOT / collector-related integration
- **`google.golang.org/grpc`** — gRPC (control plane and related RPCs)

The repo contains **multiple Go modules**; use **`mage tidy`** to keep `go.mod` files consistent when dependencies change.

## Style and code quality

### Lint Commands

```bash
mage fmt             # formats source code (.go and .py) and adds license headers.
mage format:all      # format automatically all the codes.
mage format:license  # applies the right license header.
```

### Rules enforced by tooling

CI and local checks enforce the following (details in [.golangci.yml](./.golangci.yml), [magefile.go](./magefile.go), and the Makefile):

- **Imports / format:** **`goimports`** with local prefix **`github.com/elastic`** (golangci formatters). Use **`mage fmt`** for formatting; **`mage check:all`** does not run the Go linter (see below).
- **License headers:** **`go-licenser`** with **Elastic License 2.0** (`mage check:license` / part of **`mage check:all`**). The `beats` tree is excluded because it is a submodule.
- **Lint:** **[golangci-lint](https://golangci-lint.run/)** per [.golangci.yml](./.golangci.yml). Notable rules include:
  - **`forbidigo`**: `fmt.Print*` is forbidden in most code — use structured logging (for example **zerolog**).
  - **`depguard`**: avoid legacy **`math/rand`**; prefer **`math/rand/v2`**.
  - **`gomodguard`**: blocked modules (for example deprecated error/uuid libraries) with suggested replacements.
  - **`nolintlint`**: `//nolint` must include an **explanation**.
  - **`gomoddirectives`**: `replace` directives are restricted to an allow list (see config).
- **Lint scope:** **`mage check:lint`** / **`make lint`** — changed files; **`mage check:lintAll`** / **`make lint-all`** — entire codebase. **`mage check:all`** is separate: license headers, integration-test `define.Require` validation, and docs path validation (see [magefile.go](./magefile.go) `Check.All`).
- **Heavy local / CI-style checks:** **`mage check`** (from [dev-tools/mage/target/common/check.go](./dev-tools/mage/target/common/check.go)) runs formatting, registered codegen/update deps (see `init()` in [magefile.go](./magefile.go)), **`mage tidy`**, then **`go vet`** and a clean working tree check. **`make check-ci`** runs **`mage check`**, regenerates **`NOTICE`**, Helm/Kubernetes generation targets, and **`check-no-changes`**. **`make check`** is **`check-ci`** plus **`make lint`** (golangci-lint).
- **Generated / spec artifacts:** After changing protos, specs, or generated configs, run **`mage update`** (and related targets as described in magefile doc strings). Do not hand-edit generated outputs without regenerating from source.
- **Docs structure:** **`mage check:all`** includes validation that files expected by docs generation exist (`Check.DocsFiles` in magefile).
- **Go toolchain:** Version pinned in [.go-version](./.go-version).
- **FIPS:** The codebase supports FIPS-oriented builds and tests (for example **`mage test:fIPSOnlyUnit`**, `requirefips` build tag). Crypto-related changes should remain compatible with FIPS expectations where applicable.

## Contribution hygiene

Principles and repo-specific process: [CONTRIBUTING.md](./CONTRIBUTING.md).

- **Fix the root cause**, not a short-term workaround, when possible.
- **Keep changes focused**; avoid unrelated refactors or scope creep.
- **Update docs and tests** when behavior, configuration, or operator-facing workflow changes.
- **Make non-obvious intent clear** through naming, structure, or brief “why” comments when needed.
- **Formatting:** All go files must be formatted with `go fmt` and the `goimports` tool, the `mage fmt` target can be used for this.
- **Do not modify `beats/`** for routine Elastic Agent work (submodule boundary).
- **Changelog:** For notable changes, add a fragment using **[elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool)**. Typical usage: `elastic-agent-changelog-tool new "$TITLE"` (see the tool’s [usage docs](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/usage.md)). PRs may use the **`skip-changelog`** label when appropriate; see `changelog/` for examples.
- **`go.mod` / NOTICE:** If you change **`go.mod`** or add/update Go dependencies, regenerate **`NOTICE.txt`** and **`NOTICE-fips.txt`** with `mage notice`
- **Before opening a PR (minimum):** **`mage test:unit`** and linting (**`mage check:lint`** or **`make lint`**) should pass. Also run **`mage check:all`** when your change should satisfy license + integration metadata + docs layout checks. For CI parity, use **`make check-ci`** (see [Makefile](./Makefile); note **`check-ci` does not run golangci-lint**, which CI runs in GitHub Actions) and **`make check`** when you want the linter plus the same **`check-ci`** steps.
  Commit the updated files. This is part of **`make check-ci`**. Use **`mage tidy`** so all modules in the repo stay in sync.
- **Integration / E2E:** When changes affect multi-component or Elasticsearch-backed behavior, run the relevant integration or E2E targets described in the magefile and [docs/test-framework-dev-guide.md](./docs/test-framework-dev-guide.md).

## PR Preferences

Always use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) when creating a pull request.
Always assign the author to the pull request.

Unless instructed otherwise, always add the `Team:Elastic-Agent-Control-Plane` label to the pull request.
Unless instructed otherwise, always add the `backport-active-all` label to the pull request when fixing a bug.

## Further documentation

- [README.md](./README.md) — setup, packaging, dependency hygiene
- [docs/architecture.md](./docs/architecture.md) — architecture overview
- [docs/component-specs.md](./docs/component-specs.md) — component spec format
- [docs/test-framework-dev-guide.md](./docs/test-framework-dev-guide.md) — integration tests
- [docs/local-k8s-testing.md](./docs/local-k8s-testing.md) — Kubernetes testing
- [Elastic Agent docs](https://www.elastic.co/docs) — product documentation
- [Fleet Server](https://github.com/elastic/fleet-server) - Control protocol server for managed agents

# Run macOS unit tests

Runs the root and EDOT unit-test Mage targets on the macOS runner for pull requests, supported branch pushes, and manual dispatches.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`macos-unit-tests.yml`](../macos-unit-tests.yml) |
| Trigger | Pull request, push to selected branches, or manual dispatch |

## Purpose

This workflow runs both unit-test targets on macOS with race detection enabled. Coverage is not collected, because nothing consumes the coverage profile.

## When it runs

It runs for any pull request, a push to `main`, `8.19`, or `9.*`, or `workflow_dispatch`. A concurrency group is keyed by workflow and ref; in-progress runs are canceled for refs other than `main`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `unit-tests` | Every matching event | None | Runs on `xcode-27` with a matrix of `test:unit` and `test:unitEdot`; checks out submodules and full Git history, installs make/Mage, then runs the selected target. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Mage target from the matrix. |
| Permissions | `contents: read`. |
| Outputs | Test results; no artifact upload is declared. |

## Operational notes

The checkout comment identifies full Git history as necessary for `TestGetReleaseBranches`.

The Go build and module caches are managed with `actions/cache` rather than `setup-go`'s built-in cache:

- The cache key includes the runner OS and architecture, the Mage target, the Go version, and the hashes of `go.sum` and `internal/edot/go.sum`, so each matrix job has its own cache.
- When `go.sum` changes, `restore-keys` falls back to the most recent cache for the same runner, target, and Go version.
- Only `push` runs save the cache. Pull requests restore from their base branch's cache and never save.
- The save step runs even if the tests fail or hit the test step's timeout, which is shorter than the job's timeout so there is time left to save.

## Sources

- Workflow: [`macos-unit-tests.yml`](../macos-unit-tests.yml)

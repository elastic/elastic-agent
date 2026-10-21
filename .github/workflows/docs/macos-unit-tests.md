# Run macOS unit tests

Runs the root and EDOT unit-test Mage targets on the macOS runner for pull requests, supported branch pushes, and manual dispatches.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`macos-unit-tests.yml`](../macos-unit-tests.yml) |
| Trigger | Pull request, push to selected branches, or manual dispatch |

## Purpose

This workflow runs both unit-test targets on macOS with race detection and coverage enabled.

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
| Outputs | Test and coverage results; no artifact upload is declared. |

## Operational notes

The checkout comment identifies full Git history as necessary for `TestGetReleaseBranches`.

## Sources

- Workflow: [`macos-unit-tests.yml`](../macos-unit-tests.yml)

# Run AI assistance from a pull request comment

Invokes the shared PR assistant for explicit commands or mentions in PR conversation and review comments.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-mention-in-pr.yml`](../trigger-mention-in-pr.yml) |
| Trigger | Issue comment or pull-request review comment created |

## Purpose

The workflow routes `/ai` commands or `@claude` mentions on pull requests to `gh-aw-mention-in-pr.lock.yml`.

## When it runs

It listens for created `issue_comment` and `pull_request_review_comment` events. The job requires a matching comment body and confirms the event is associated with a pull request.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Comment passes the PR and command checks | None | Calls the external PR assistant with setup commands. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: write`, `copilot-requests: write`, `discussions: write`, `id-token: write`, `issues: write`, `pull-requests: write`. |
| Outputs | The external workflow handles the assistant response and any resulting PR activity. |

## Operational notes

The reusable assistant implementation is not checked in here. The caller installs repository tooling through its setup commands.

## Sources

- Workflow: [`trigger-mention-in-pr.yml`](../trigger-mention-in-pr.yml)

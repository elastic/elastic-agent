# Run AI assistance from an issue comment

Invokes the shared issue-comment assistant for eligible comments on non-pull-request issues.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-mention-in-issue.yml`](../trigger-mention-in-issue.yml) |
| Trigger | Issue comment created |

## Purpose

The workflow routes explicit `/ai` commands or `@claude` mentions on issues to `gh-aw-mention-in-issue.lock.yml`.

## When it runs

It listens to `issue_comment:created`; the job requires the issue not to be a pull request and the comment body to start with `/ai` or contain `@claude`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Comment matches the issue-only condition | None | Calls the external mention workflow with setup commands and an instruction to label any created PR `ai`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: write`, `copilot-requests: write`, `discussions: write`, `issues: write`, `pull-requests: write`. |
| Outputs | The external workflow may respond to the comment or create repository changes. |

## Operational notes

The assistant implementation is external. The caller's setup commands install required system libraries and Mage.

## Sources

- Workflow: [`trigger-mention-in-issue.yml`](../trigger-mention-in-issue.yml)

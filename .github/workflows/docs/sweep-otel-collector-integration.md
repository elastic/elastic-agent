# Sweep OTel Collector integration

Runs a scheduled code-quality audit focused on OTel Collector configuration translation, status, subprocess lifecycle, and data handling.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`sweep-otel-collector-integration.yml`](../sweep-otel-collector-integration.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The inline instructions direct the shared audit workflow to investigate Elastic Agent's OTel integration and report only issues that can affect a real deployment.

## When it runs

Runs on a schedule or when manually dispatched. No branch/path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external code-quality audit workflow with a high severity threshold, setup commands, and OTel-specific audit instructions. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | The external workflow is instructed to file one issue for confirmed findings; `report-failure-as-issue` is false. |

## Operational notes

The reusable audit implementation is external; its prompt requests evidence and tests for confirmed findings. Setup installs system libraries and builds Mage.

## Sources

- Workflow: [`sweep-otel-collector-integration.yml`](../sweep-otel-collector-integration.yml)

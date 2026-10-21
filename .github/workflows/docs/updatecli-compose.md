# Apply composed Updatecli policies

Runs Updatecli Compose on a schedule or manual dispatch to apply the configured dependency policies.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`updatecli-compose.yml`](../updatecli-compose.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow runs Updatecli Compose against the repository's [`updatecli-compose.yaml`](../../../updatecli-compose.yaml), whose checked-in policy list includes OBLT CLI version, Iron Bank templates, and Updatecli policy updates.

## When it runs

Runs on a schedule or when manually dispatched, with no branch or path filters.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `compose` | Every matching event | None | Checks out the repository, obtains a token, logs in to GHCR, runs `compose apply` using the pinned Updatecli version, and notifies Slack on failure. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Workflow grants `contents: read`; job grants `contents: read`, `id-token: write`, and `packages: read`. |
| Outputs | Updatecli policies may open pull requests; outcomes depend on the remote policy definitions. |
| Secrets | `GITHUB_TOKEN` for GHCR login; `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The remote policies are hosted in GHCR and are not checked into this repository. Their local values are under [`.ci/updatecli/values.d/`](../../../.ci/updatecli/values.d/); `.updatecli-version` selects the Updatecli release.

## Sources

- Workflow: [`updatecli-compose.yml`](../updatecli-compose.yml)
- Compose configuration: [`updatecli-compose.yaml`](../../../updatecli-compose.yaml)
- Version pin: [`.updatecli-version`](../../../.updatecli-version)
- Local values: [`values.d`](../../../.ci/updatecli/values.d/)

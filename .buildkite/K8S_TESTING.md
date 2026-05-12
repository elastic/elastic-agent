# Kubernetes Testing Tiers

Kubernetes integration tests are organized into three tiers to optimize CI resources.

## Decision Flow

```mermaid
flowchart TD
    Start([Build Triggered]) --> CheckScheduled{Scheduled build?<br/>K8S_SCHEDULED_TIER3=true}
    
    CheckScheduled -->|Yes| Tier3[Tier 3<br/>8 K8s versions × 9 variants<br/>72 jobs]
    CheckScheduled -->|No| CheckPR{Pull Request?}
    
    CheckPR -->|No<br/>Branch build| Tier2_Branch[Tier 2<br/>2 K8s versions × 9 variants<br/>18 jobs]
    CheckPR -->|Yes| CheckPackaging{Packaging files<br/>modified?}
    
    CheckPackaging -->|Yes<br/>.buildkite/, magefile.go,<br/>dev-tools/, go.mod/sum| Tier2_PR[Tier 2<br/>2 K8s versions × 9 variants<br/>18 jobs]
    CheckPackaging -->|No| Tier1[Tier 1<br/>2 K8s versions × 1 variant<br/>2 jobs]
    
    Tier1 --> Upload[Upload k8s-testing-pipeline.yml]
    Tier2_PR --> Upload
    Tier2_Branch --> Upload
    Tier3 --> Upload
    
    Upload --> Run[Run K8s Integration Tests]
    
    style Tier1 fill:#d4edda,stroke:#28a745
    style Tier2_PR fill:#fff3cd,stroke:#ffc107
    style Tier2_Branch fill:#fff3cd,stroke:#ffc107
    style Tier3 fill:#f8d7da,stroke:#dc3545
```

## Tier Definitions

| Tier | K8s Versions | Container Images | When Used | Job Count |
|------|--------------|------------------|-----------|-----------|
| **Tier 1** | Min + Max (2) | Basic only (1) | PRs (default) | 2 |
| **Tier 2** | Min + Max (2) | All (9) | Branch builds, packaging PRs | 18 |
| **Tier 3** | All (8) | All (9) | Scheduled (daily) | 72 |

## Triggers

- **PRs**: Tier 1 by default, Tier 2 if packaging files modified
- **Branches**: Tier 2 on every commit
- **Scheduled**: Tier 3 daily at 2:00 AM UTC

### Packaging Files

PRs trigger Tier 2 when modifying:
- `.buildkite/**`
- `magefile.go`
- `dev-tools/**`
- `go.mod` / `go.sum`

## Implementation

1. **[.buildkite/scripts/upload-k8s-tests.sh](.buildkite/scripts/upload-k8s-tests.sh)** - Determines tier and uploads pipeline
2. **[.buildkite/k8s-testing-pipeline.yml](.buildkite/k8s-testing-pipeline.yml)** - Dynamic test pipeline template
3. **[.github/workflows/k8s-tier3-scheduled.yml](../.github/workflows/k8s-tier3-scheduled.yml)** - Scheduled Tier 3 trigger

## Updating K8s Versions

Update these variables in `.buildkite/scripts/upload-k8s-tests.sh`:
- `K8S_MIN_VERSION`
- `K8S_MAX_VERSION`
- `K8S_ALL_VERSIONS` (array)

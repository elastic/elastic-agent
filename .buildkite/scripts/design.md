
```mermaid
flowchart TD
    subgraph GitHub["GitHub Events"]
        PR[Pull Request<br/>to main/8.*]
        Push[Push to<br/>main/8.*]
        Schedule[Schedule<br/>Daily 2:00 AM UTC]
        Manual[Manual Trigger<br/>workflow_dispatch]
    end
    
    subgraph GitHubActions["GitHub Actions"]
        GHA_K8s[kubernetes-integration-tests.yml<br/>Self-contained K8s tests<br/>PR: 2 versions × 9 variants<br/>Main: 8 versions × 2 variant groups]
        GHA_Scheduled[k8s-tier3-scheduled.yml<br/>Triggers Buildkite via API]
    end
    
    subgraph Buildkite["Buildkite Pipeline"]
        BK_Main[bk.integration.pipeline.yml<br/>Main integration pipeline]
        BK_Upload[upload-k8s-tests.sh<br/>Determines tier &<br/>generates dynamic pipeline YAML]
        BK_Generated[Generated Pipeline YAML<br/>Matrix embedded with<br/>versions & variants]
    end
    
    PR --> GHA_K8s
    Push --> GHA_K8s
    PR -.-> BK_Main
    Push -.-> BK_Main
    
    Schedule --> GHA_Scheduled
    Manual --> GHA_Scheduled
    
    GHA_Scheduled -->|Buildkite API call<br/>Sets K8S_SCHEDULED_TIER3=true| BK_Main
    
    BK_Main -->|Kubernetes group step| BK_Upload
    BK_Upload -->|Generates & uploads pipeline| BK_Generated
    
    BK_Upload -.->|Tier 1/2/3 decision| Decision{Tier Selection}
    
    Decision -->|Tier 1<br/>PR + no packaging changes| Config1[2 versions × 1 variant<br/>basic only]
    Decision -->|Tier 2<br/>PR + packaging changes<br/>OR branch build| Config2[2 versions × 9 variants<br/>all variants]
    Decision -->|Tier 3<br/>K8S_SCHEDULED_TIER3=true| Config3[8 versions × 9 variants<br/>all variants]
    
    Config1 -.->|Matrix config| BK_Generated
    Config2 -.->|Matrix config| BK_Generated
    Config3 -.->|Matrix config| BK_Generated
    
    style GHA_K8s fill:#1a4d6d,stroke:#29b6f6,color:#fff
    style GHA_Scheduled fill:#6d4d1a,stroke:#ff9800,color:#fff
    style BK_Main fill:#4d1a6d,stroke:#ab47bc,color:#fff
    style BK_Upload fill:#1a6d3a,stroke:#66bb6a,color:#fff
    style BK_Generated fill:#6d5d1a,stroke:#ffca28,color:#fff
    style Decision fill:#6d1a1a,stroke:#ef5350,color:#fff
```

## How It Works

### GitHub Actions Path

**kubernetes-integration-tests.yml**
- Triggered on PR and push events to `main` and `8.*` branches
- Self-contained: packages containers, sets up ESS stack, runs tests
- Two different job strategies:
  - **PR builds**: `kubernetes-tests-pr` job
    - Matrix: 2 versions (v1.27.16, v1.34.0) × 9 variants individually
    - Creates 18 parallel jobs
    - Each job tests one version + one variant combination
  - **Non-PR builds**: `kubernetes-tests-main` job
    - Matrix: 8 versions × 2 variant groups
    - Variant groups: `basic,slim,complete,service,elastic-otel-collector` and `wolfi,slim-wolfi,complete-wolfi,elastic-otel-collector-wolfi`
    - Creates 16 parallel jobs
    - Each job tests one version with multiple variants (comma-separated in DOCKER_VARIANTS)

**k8s-tier3-scheduled.yml**
- Scheduled daily at 2:00 AM UTC or manually triggered via workflow_dispatch
- Triggers a Buildkite build via API call with environment variable `K8S_SCHEDULED_TIER3=true`
- Target: `elastic/elastic-agent` Buildkite pipeline

### Buildkite Path

**bk.integration.pipeline.yml**
- Main integration pipeline containing the Kubernetes group step
- The group depends on `integration-ess` (ESS stack) and `packaging-containers-amd64` (container artifacts)
- Contains a single step: `"Upload k8s tests pipeline"` which executes `upload-k8s-tests.sh`

**upload-k8s-tests.sh** (The Orchestrator)

This script is the heart of the dynamic pipeline generation. It:

1. **Determines the test tier** based on build context:
   - **Tier 1**: PR builds with no packaging file changes
     - Triggers when: PR + no changes to `.buildkite/`, `magefile.go`, `dev-tools/`, `go.mod`, `go.sum`
     - Config: 2 versions (min/max) × 1 variant (basic)
   
   - **Tier 2**: PR builds with packaging changes OR branch builds
     - Triggers when: PR + packaging file changes OR non-PR build
     - Config: 2 versions (min/max) × 9 variants (all)
   
   - **Tier 3**: Scheduled comprehensive tests
     - Triggers when: `K8S_SCHEDULED_TIER3=true` environment variable is set
     - Config: 8 versions (all) × 9 variants (all)

2. **Generates a complete pipeline YAML** with:
   - Common plugin definitions (google_oidc, oblt_cli, vault)
   - A single step template with `{{matrix.version}}` and `{{matrix.variant}}` placeholders
   - Embedded matrix configuration with the appropriate versions and variants arrays

3. **Uploads the generated pipeline** using `buildkite-agent pipeline upload`
   - Buildkite expands the matrix and creates individual jobs for each combination
   - Example: Tier 3 = 8 versions × 9 variants = 72 parallel jobs

### Key Design Points

1. **No static k8s-testing-pipeline.yml file**: The pipeline YAML is generated on-the-fly by `upload-k8s-tests.sh` based on the tier

2. **Packaging change detection**: The script checks if packaging-related files were modified in the PR to determine if Tier 2 testing is needed

3. **Matrix expansion**: Buildkite's native matrix feature expands the uploaded pipeline into individual jobs

4. **Artifact dependencies**: All jobs download the container artifacts from the `packaging-containers-amd64` step

5. **Version consistency**: K8s min/max versions are defined in both `upload-k8s-tests.sh` and the main integration pipeline for synchronization

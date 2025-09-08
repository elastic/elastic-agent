# Overview

This is how we manage adhoc dependency updates using `updatecli`.

## EDOT SDK Dependencies Update Automation

This directory contains updatecli configuration to automatically update EDOT SDK docker image versions in the elastic-agent repository.

### Overview

The automation tracks latest releases from the following repositories and updates corresponding docker image references in elastic-agent:

- **elastic/elastic-otel-dotnet** → `docker.elastic.co/observability/elastic-otel-dotnet`
- **elastic/elastic-otel-java** → `docker.elastic.co/observability/elastic-otel-javaagent`
- **elastic/elastic-otel-node** → `docker.elastic.co/observability/elastic-otel-node`
- **elastic/elastic-otel-python** → `docker.elastic.co/observability/elastic-otel-python`
- **open-telemetry/opentelemetry-go-instrumentation** → `ghcr.io/open-telemetry/opentelemetry-go-instrumentation/autoinstrumentation-go`

### Files Updated

The automation updates these files in the elastic-agent repository:
- `deploy/helm/edot-collector/kube-stack/managed_otlp/values.yaml`
- `deploy/helm/edot-collector/kube-stack/values.yaml`

Specifically, it updates the `instrumentation` section with the latest versions:

```yaml
instrumentation:
  java:
    image: docker.elastic.co/observability/elastic-otel-javaagent:X.Y.Z
  nodejs:
    image: docker.elastic.co/observability/elastic-otel-node:X.Y.Z
  dotnet:
    image: docker.elastic.co/observability/elastic-otel-dotnet:X.Y.Z
  python:
    image: docker.elastic.co/observability/elastic-otel-python:X.Y.Z
  go:
    image: ghcr.io/open-telemetry/opentelemetry-go-instrumentation/autoinstrumentation-go:vX.Y.Z
```

### Configuration Files

- **`bump-edot-images.yml`**: Main updatecli configuration that defines sources and targets
- **`values.d/scm.yml`**: Contains SCM configuration values for GitHub authentication

### GitHub Workflow

The automation runs via GitHub workflow `.github/workflows/bump-edot-images.yml` which:
- Runs Monday to Friday at 3 PM UTC
- Can be triggered manually via workflow_dispatch
- Uses the OBS_AUTOMATION_APP credentials for creating PRs
- Creates pull requests with `dependencies`, `skip-changelog`, and backport labels.

### Example Output

When new versions are detected, the automation will create a pull request similar to [elastic-agent#7327](https://github.com/elastic/elastic-agent/pull/7327) that was manually created previously.

### Version Handling

The configuration handles different version formatting:
- Some repositories use `v` prefix in their tags (like `v1.2.0`)
- The automation strips the `v` prefix where needed to match the expected docker tag format
- Go instrumentation keeps the `v` prefix as that's the expected format

### Manual Testing

To test the configuration locally:

```bash
export GITHUB_TOKEN=$(gh auth token)
export GITHUB_ACTOR=v1v
updatecli diff \
    --config .ci/updatecli/bump-edot-images.yml \
    --values .ci/updatecli/values.d/scm.yml
# Apply changes (requires write access to elastic-agent repo)
updatecli apply \
    --config .ci/updatecli/bump-edot-images.yml \
    --values .ci/updatecli/values.d/scm.yml
```

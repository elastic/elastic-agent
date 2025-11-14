<!--
(NOTE: AI was used on this file)
-->

# Contributing to Elastic Agent Helm Chart

This is an **INCOMPLETE** set of tips and explanations for developers who want
to modify or contribute to the Elastic Agent Helm chart.

## Testing Your Changes Locally

By default, the agent is installed on the `kube-system` namespace. Thus you'll
need to pass `-n kube-system` to the `helm` invocations that interact with the
k8s cluster.

### Rendering the Chart

Use `helm template` to render the chart and verify the output without actually
installing it:

```bash
# Using a values file
helm template elastic-agent . -f values.yaml

# Or setting values directly
helm template elastic-agent . --set kubernetes.enabled=true --set outputs.default.type=ESPlainAuthAPI
```

This works just like `helm install` but only generates the Kubernetes manifests
without applying them to the cluster.

### Testing with Different Examples

Test your changes against the example configurations in the `examples/` directory:

```bash
helm template elastic-agent . -f examples/kubernetes-default/agent-kubernetes-values.yaml
```

### Applying Changes to an Existing Deployment

If you have already installed the chart and want to test modifications, use
`helm upgrade`:

```bash
# Using a values file
helm upgrade elastic-agent . -f your-values.yaml

# Or using --set to override specific values
helm upgrade elastic-agent . --set agent.version=9.3.0

# Combine both approaches
helm upgrade elastic-agent . -f your-values.yaml --set kubernetes.enabled=false
```

## Editing the README

The README.md was originally generated using [helm-docs](https://github.com/norwoodj/helm-docs).
However, it has diverged from the auto-generated version since.
`helm-docs` is still usefull to can pick up changes to the `values.yaml` and
format them as the others. However, running it will completely override the
README.md.
You might use `helm-docs` to render the changes you made to `values.yaml`. Then,
find you changes, copy it, restore the README.md and manually add your changes.


### Adding New Values Documentation

When you add new values to `values.yaml`, make sure to:
1. Add appropriate comments above the value (helm-docs uses these)
2. Update the schema in `values.schema.json` accordingly

Example format in `values.yaml`:
```yaml
# -- Enable the new feature
# @section -- 6 - Elastic-Agent Configuration
newFeature:
  # -- Enable/disable the feature
  enabled: false
  # -- Configuration for the feature
  config: {}
```


## Useful Commands Reference

```bash
# Install chart in a cluster with values file
helm install elastic-agent . -f values.yaml -n kube-system

# Install chart with --set flags
helm install elastic-agent . --set outputs.default.type=ESPlainAuthAPI --set outputs.default.api_key=your_key -n kube-system

# Combine values file and --set (--set takes precedence)
helm install elastic-agent . -f values.yaml --set agent.version=9.3.0 -n kube-system

# Upgrade existing installation
helm upgrade elastic-agent . -f values.yaml -n kube-system

# Dry-run to see what would change
helm upgrade elastic-agent . -f values.yaml -n kube-system --dry-run --debug

# Uninstall
helm uninstall elastic-agent -n kube-system
```

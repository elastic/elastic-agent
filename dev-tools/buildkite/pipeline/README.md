# Buildkite Pipeline Generator

This package provides a Go API for generating Buildkite pipeline YAML files programmatically using the official Buildkite SDK.

## Overview

Instead of maintaining YAML files directly, pipelines are defined in Go code. This provides:

- **Type safety**: Catch configuration errors at compile time
- **Reusability**: Share common configurations (agents, plugins, env vars) across pipelines
- **Testability**: Unit test pipeline generation and compare against expected output
- **Maintainability**: Refactor and update pipelines using standard Go tooling

## Quick Start

```go
package main

import (
    "github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

func main() {
    // Create a command step
    step := pipeline.CommandWithKey("Unit tests", "unit-tests", ".buildkite/scripts/steps/unit-tests.sh")
    pipeline.SetAgent(step, pipeline.GCPAgent(pipeline.ImageUbuntu2204X86, pipeline.MachineTypeN2Standard8))
    pipeline.SetArtifactPaths(step, "build/TEST-*.xml")
    pipeline.SetRetry(step, 1, true)
    pipeline.WithVaultDockerLogin(step)

    // Create a trigger step
    trigger := pipeline.Trigger("Trigger downstream", "downstream-pipeline")
    pipeline.SetTriggerIf(trigger, "build.pull_request.id == null")

    // Build the pipeline
    p := pipeline.New().
        Env("VAULT_PATH", pipeline.VaultPathGCP).
        WithImageEnvVars().
        Add(step).
        Wait().
        Add(trigger)

    if err := p.WriteYAML(".buildkite/pipeline.yml"); err != nil {
        panic(err)
    }
}
```

## API Reference

### Pipeline

```go
// Create a new pipeline
p := pipeline.New()

// Add environment variables
p.Env("KEY", "value")
p.EnvMap(map[string]string{"KEY1": "val1", "KEY2": "val2"})
p.WithImageEnvVars() // Adds all standard VM image env vars

// Add steps
p.Add(step)  // Accepts CommandStep, GroupStep, TriggerStep, InputStep, BlockStep
p.Wait()     // Add wait step

// Output
yaml, err := p.MarshalYAML()
err := p.WriteYAML("path/to/pipeline.yml")
```

### Command Steps

```go
// Create command steps
step := pipeline.Command("Label", "command")
step := pipeline.CommandWithKey("Label", "key", "command")

// Configure command steps
pipeline.SetAgent(step, agent)
pipeline.SetEnv(step, map[string]string{"KEY": "value"})
pipeline.AddEnv(step, "KEY", "value")
pipeline.SetArtifactPaths(step, "path1", "path2")
pipeline.SetRetry(step, automaticLimit, manualAllowed)
pipeline.SetRetryAutomatic(step, limit)
pipeline.SetRetryManual(step)
pipeline.SetDependsOn(step, "other-step")
pipeline.SetDependsOnWithFailure(step, pipeline.DependsOnDep{Step: "s1", AllowFailure: true})
pipeline.SetMatrix(step, map[string][]string{"os": {"linux", "windows"}})
pipeline.SetSimpleMatrix(step, []string{"a", "b", "c"})
pipeline.SetIf(step, "build.pull_request.id != null")
pipeline.SetBranches(step, "main 8.* 9.*")
pipeline.SetTimeout(step, 60)
pipeline.SetParallelism(step, 4)
pipeline.SetNotify(step, "buildkite/context")
pipeline.AddPlugin(step, source, config)
```

### Group Steps

```go
// Create group steps
group := pipeline.Group("Label")
group := pipeline.GroupWithKey("Label", "key")

// Configure group steps
pipeline.AddGroupStep(group, step)
pipeline.SetGroupDependsOn(group, "previous")
pipeline.SetGroupNotify(group, "buildkite/context")
```

### Trigger Steps

```go
// Create trigger steps
trigger := pipeline.Trigger("Label", "pipeline-slug")

// Configure trigger steps
pipeline.SetTriggerIf(trigger, "condition")
pipeline.SetTriggerAsync(trigger, true)
pipeline.SetTriggerBranches(trigger, "main")
pipeline.SetTriggerBuild(trigger, commit, branch, envMap)
```

### Input Steps

```go
// Create input steps
input := pipeline.Input("Build parameters")

// Configure input steps
pipeline.SetInputIf(input, "condition")
pipeline.AddInputField(input, "Label", "key", "default", "hint", required)
pipeline.AddSelectField(input, "Label", "key", "hint", required,
    pipeline.SelectOption{Label: "Yes", Value: "1"},
    pipeline.SelectOption{Label: "No", Value: "0"},
)
```

### Block Steps

```go
block := pipeline.Block("Approval required")
```

## Agent Configuration

```go
// GCP agents
pipeline.GCPAgent(image, machineType)
pipeline.GCPAgentWithDisk(image, machineType, diskSizeGB, diskType)

// AWS agents
pipeline.AWSAgent(image, instanceType)
pipeline.AWSAgentWithDisk(image, instanceType, diskSizeGB)

// Orka agents (macOS)
pipeline.OrkaAgent(imagePrefix)

// Docker agents
pipeline.DockerAgent(image)
pipeline.DockerAgentWithHooks(image)

// Presets
pipeline.AgentUbuntu2204X86Standard8
pipeline.AgentUbuntu2204ARMM6gXLarge
pipeline.AgentWin2022Standard8
pipeline.AgentMacOS15ARM
pipeline.AgentMacOS13X86
pipeline.BeatsCI()
pipeline.JunitAnnotateAgent()
```

## Plugin Configuration

```go
// Add plugins to steps
pipeline.WithVaultDockerLogin(step)
pipeline.WithVaultECKeyProd(step)
pipeline.WithGoogleOIDC(step)
pipeline.WithGCPSecretManagerServerless(step)
pipeline.WithJunitAnnotate(step, artifactPattern)
pipeline.WithTestCollector(step, filesPattern, format)

// Get plugin source and config for manual addition
source, config := pipeline.PluginVaultDockerLogin()
source, config := pipeline.PluginVaultSecrets(path, field, envVar)
source, config := pipeline.PluginGCPSecretManager(envSecrets)
source, config := pipeline.PluginGoogleOIDC()
source, config := pipeline.PluginJunitAnnotate(artifactPattern)
source, config := pipeline.PluginTestCollector(filesPattern, format)
```

## Constants

### VM Images

```go
pipeline.ImageUbuntu2204X86  // Ubuntu 22.04 x86_64
pipeline.ImageUbuntu2204ARM  // Ubuntu 22.04 ARM64
pipeline.ImageUbuntu2404X86  // Ubuntu 24.04 x86_64
pipeline.ImageUbuntu2404ARM  // Ubuntu 24.04 ARM64
pipeline.ImageWin2022        // Windows Server 2022
pipeline.ImageWin2025        // Windows Server 2025
pipeline.ImageRHEL8          // RHEL 8
pipeline.ImageRHEL10         // RHEL 10
pipeline.ImageDebian11       // Debian 11
pipeline.ImageDebian13       // Debian 13
```

### Machine Types

```go
pipeline.MachineTypeN2Standard8  // GCP n2-standard-8
pipeline.InstanceTypeM6gXLarge   // AWS m6g.xlarge
pipeline.DiskSize200GB           // 200 GB disk
```

### Vault Paths

```go
pipeline.VaultPathGCP            // GCP vault path
pipeline.VaultPathDockerRegistry // Docker registry credentials
pipeline.VaultPathECKeyProd      // EC production API key
```

## Testing

The package includes utilities for testing pipeline generation:

```go
// Compare generated pipeline with existing YAML file
result, err := pipeline.CompareWithFile(p, ".buildkite/pipeline.yml")
if !result.Equal {
    t.Errorf("pipelines differ:\n%s", result.Diff)
}

// Compare two YAML representations
result, err := pipeline.Compare(generated, expected)
```

## Migration Strategy

1. **Start with simpler pipelines**: Begin migrating less complex pipelines first
2. **Add parity tests**: Create tests that compare generated YAML with existing files
3. **Keep both during transition**: Maintain both YAML and Go during migration
4. **Validate before switching**: Ensure generated YAML passes schema validation
5. **Switch source of truth**: Once confident, generate YAML from Go in CI

## Directory Structure

```
dev-tools/buildkite/
├── pipeline/           # This package - core types and helpers
│   ├── agents.go       # Agent configuration helpers
│   ├── images.go       # VM image constants
│   ├── pipeline.go     # Pipeline wrapper
│   ├── plugins.go      # Plugin configuration helpers
│   └── step.go         # Step creation and configuration helpers
└── pipelines/          # Pipeline definitions (future)
    ├── main.go         # pipeline.yml
    └── integration.go  # integration.pipeline.yml
```

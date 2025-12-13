// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

// Agent represents a Buildkite agent configuration.
// It is serialized as a map in the YAML output.
type Agent map[string]any

// GCPAgent creates an agent configuration for Google Cloud Platform.
func GCPAgent(image, machineType string) Agent {
	return Agent{
		"provider":    "gcp",
		"image":       image,
		"machineType": machineType,
	}
}

// GCPAgentWithDisk creates a GCP agent configuration with custom disk settings.
func GCPAgentWithDisk(image, machineType string, diskSizeGB int, diskType string) Agent {
	a := GCPAgent(image, machineType)
	a["diskSizeGb"] = diskSizeGB
	if diskType != "" {
		a["disk_type"] = diskType
	}
	return a
}

// AWSAgent creates an agent configuration for Amazon Web Services.
func AWSAgent(image, instanceType string) Agent {
	return Agent{
		"provider":     "aws",
		"image":        image,
		"instanceType": instanceType,
	}
}

// AWSAgentWithDisk creates an AWS agent configuration with custom disk size.
func AWSAgentWithDisk(image, instanceType string, diskSizeGB int) Agent {
	a := AWSAgent(image, instanceType)
	a["diskSizeGb"] = diskSizeGB
	return a
}

// OrkaAgent creates an agent configuration for Orka (macOS).
func OrkaAgent(imagePrefix string) Agent {
	return Agent{
		"provider":    "orka",
		"imagePrefix": imagePrefix,
	}
}

// DockerAgent creates an agent configuration that runs in a Docker container.
func DockerAgent(image string) Agent {
	return Agent{
		"image": image,
	}
}

// DockerAgentWithHooks creates a Docker agent with custom global hooks enabled.
func DockerAgentWithHooks(image string) Agent {
	return Agent{
		"image":                image,
		"useCustomGlobalHooks": true,
	}
}

// WithDiskSize adds disk size configuration to an existing agent.
func (a Agent) WithDiskSize(sizeGB int) Agent {
	a["diskSizeGb"] = sizeGB
	return a
}

// WithDiskType adds disk type configuration to an existing agent (GCP only).
func (a Agent) WithDiskType(diskType string) Agent {
	a["disk_type"] = diskType
	return a
}

// WithMachineType sets the machine type (GCP) or instance type (AWS).
func (a Agent) WithMachineType(machineType string) Agent {
	if a["provider"] == "aws" {
		a["instanceType"] = machineType
	} else {
		a["machineType"] = machineType
	}
	return a
}

// Clone creates a copy of the agent configuration.
func (a Agent) Clone() Agent {
	clone := make(Agent, len(a))
	for k, v := range a {
		clone[k] = v
	}
	return clone
}

// Common agent presets for frequently used configurations.
var (
	// AgentUbuntu2204X86Standard8 is a standard Ubuntu 22.04 x86_64 agent on GCP.
	AgentUbuntu2204X86Standard8 = GCPAgent(ImageUbuntu2204X86, MachineTypeN2Standard8)

	// AgentUbuntu2204ARMM6gXLarge is a standard Ubuntu 22.04 ARM64 agent on AWS.
	AgentUbuntu2204ARMM6gXLarge = AWSAgent(ImageUbuntu2204ARM, InstanceTypeM6gXLarge)

	// AgentUbuntu2404X86Standard8 is a standard Ubuntu 24.04 x86_64 agent on GCP.
	AgentUbuntu2404X86Standard8 = GCPAgent(ImageUbuntu2404X86, MachineTypeN2Standard8)

	// AgentUbuntu2404ARMM6g2XLarge is a standard Ubuntu 24.04 ARM64 agent on AWS.
	AgentUbuntu2404ARMM6g2XLarge = AWSAgent(ImageUbuntu2404ARM, InstanceTypeM6g2XLarge)

	// AgentWin2022Standard8 is a standard Windows 2022 agent on GCP.
	AgentWin2022Standard8 = GCPAgentWithDisk(ImageWin2022, MachineTypeN2Standard8, DiskSize200GB, "pd-ssd")

	// AgentWin2016Standard8 is a standard Windows 2016 agent on GCP.
	AgentWin2016Standard8 = GCPAgentWithDisk(ImageWin2016, MachineTypeN2Standard8, DiskSize200GB, "pd-ssd")

	// AgentMacOS15ARM is a macOS 15 ARM agent on Orka.
	AgentMacOS15ARM = OrkaAgent("generic-base-15-arm-002")

	// AgentMacOS13X86 is a macOS 13 x86_64 agent on Orka.
	AgentMacOS13X86 = OrkaAgent("generic-13-ventura-x64")
)

// BeatsCI returns the standard Beats CI Docker agent.
func BeatsCI() Agent {
	return DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5")
}

// JunitAnnotateAgent returns the agent for junit annotation steps.
func JunitAnnotateAgent() Agent {
	return DockerAgent("docker.elastic.co/ci-agent-images/buildkite-junit-annotate:1.0")
}

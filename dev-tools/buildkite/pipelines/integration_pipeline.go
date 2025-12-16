// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// IntegrationPipeline generates the .buildkite/integration.pipeline.yml pipeline.
// This pipeline handles packaging and triggers integration tests.
func IntegrationPipeline() *pipeline.Pipeline {
	p := pipeline.New().
		Env("VAULT_PATH", pipeline.VaultPathGCP).
		Env("ASDF_MAGE_VERSION", "1.14.0").
		Env("BUILDKIT_PROGRESS", "plain").
		Env("IMAGE_UBUNTU_2204_X86_64", pipeline.ImageUbuntu2204X86).
		Env("IMAGE_UBUNTU_2204_ARM_64", pipeline.ImageUbuntu2204ARM)

	// Integration tests: packaging group
	p.Add(packagingGroup())

	// Trigger integration tests
	triggerIntegration := pipeline.Command("Triggering Integration tests", "buildkite-agent pipeline upload .buildkite/bk.integration.pipeline.yml")
	p.Add(triggerIntegration)

	// Trigger FIPS integration tests
	triggerFips := pipeline.Command("Triggering custom FIPS integration tests", "buildkite-agent pipeline upload .buildkite/bk.integration-fips.pipeline.yml")
	p.Add(triggerFips)

	return p
}

// packagingGroup creates the "Integration tests: packaging" group.
func packagingGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Integration tests: packaging", "int-packaging")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent - Packaging")

	// Packaging amd64 non-containers
	amd64 := packagingStep(
		":package: amd64: zip,tar.gz,rpm,deb ",
		"packaging-amd64",
		"windows/amd64,linux/amd64",
		"zip,tar.gz,rpm,deb",
		false, // not FIPS
		false, // not OTEL
		"gcp",
		pipeline.MachineTypeN2Standard8,
		"${IMAGE_UBUNTU_2204_X86_64}",
		0, // no extra disk
		false,
	)
	pipeline.AddGroupStep(group, amd64)

	// Packaging amd64 OTEL_COMPONENT
	amd64Otel := packagingStep(
		":package: amd64: OTEL_COMPONENT zip,tar.gz,rpm,deb ",
		"packaging-amd64-otel-component",
		"windows/amd64,linux/amd64",
		"zip,tar.gz,rpm,deb",
		false,
		true, // OTEL
		"gcp",
		pipeline.MachineTypeN2Standard8,
		"${IMAGE_UBUNTU_2204_X86_64}",
		0,
		false,
	)
	pipeline.AddGroupStep(group, amd64Otel)

	// Packaging amd64 FIPS tar.gz
	amd64Fips := packagingStep(
		":package: amd64: FIPS tar.gz",
		"packaging-amd64-fips",
		"linux/amd64",
		"tar.gz",
		true, // FIPS
		false,
		"gcp",
		"n2-standard-4",
		"${IMAGE_UBUNTU_2204_X86_64}",
		0,
		false,
	)
	pipeline.AddGroupStep(group, amd64Fips)

	// Packaging arm64 zip,tar.gz
	arm64 := packagingStep(
		":package: arm64: zip,tar.gz",
		"packaging-arm64",
		"windows/arm64,linux/arm64",
		"tar.gz,zip",
		false,
		false,
		"aws",
		"c6g.2xlarge",
		"${IMAGE_UBUNTU_2204_ARM_64}",
		0,
		false,
	)
	pipeline.AddGroupStep(group, arm64)

	// Packaging arm64 OTEL_COMPONENT
	arm64Otel := packagingStep(
		":package: arm64: OTEL_COMPONENT zip,tar.gz",
		"packaging-arm64-otel-component",
		"windows/arm64,linux/arm64",
		"tar.gz,zip",
		false,
		true,
		"aws",
		"c6g.2xlarge",
		"${IMAGE_UBUNTU_2204_ARM_64}",
		0,
		false,
	)
	pipeline.AddGroupStep(group, arm64Otel)

	// Packaging arm64 FIPS tar.gz
	arm64Fips := packagingStep(
		":package: arm64: FIPS tar.gz",
		"packaging-arm64-fips",
		"linux/arm64",
		"tar.gz",
		true,
		false,
		"aws",
		"c6g.2xlarge",
		"${IMAGE_UBUNTU_2204_ARM_64}",
		0,
		false,
	)
	pipeline.AddGroupStep(group, arm64Fips)

	// Container steps
	// amd64 containers
	containersAmd64 := containerPackagingStep(
		":package: amd64: Containers",
		"packaging-containers-amd64",
		"linux/amd64",
		false,
		false,
		"gcp",
		pipeline.MachineTypeN2Standard8,
		"${IMAGE_UBUNTU_2204_X86_64}",
		true, // includes cloud image push
		true, // needs docker login
	)
	pipeline.AddGroupStep(group, containersAmd64)

	// arm64 containers
	containersArm64 := containerPackagingStep(
		":package: arm64: Containers",
		"packaging-containers-arm64",
		"linux/arm64",
		false,
		false,
		"aws",
		"c6g.4xlarge",
		"${IMAGE_UBUNTU_2204_ARM_64}",
		false, // no cloud image push
		false, // no docker login
	)
	pipeline.AddGroupStep(group, containersArm64)

	// amd64 FIPS containers
	containersFipsAmd64 := containerPackagingStep(
		":package: amd64: FIPS Containers",
		"packaging-containers-amd64-fips",
		"linux/amd64",
		true,
		false,
		"gcp",
		pipeline.MachineTypeN2Standard8,
		"${IMAGE_UBUNTU_2204_X86_64}",
		true,
		true,
	)
	pipeline.AddGroupStep(group, containersFipsAmd64)

	// arm64 FIPS containers
	containersFipsArm64 := containerPackagingStep(
		":package: arm64: FIPS Containers",
		"packaging-containers-arm64-fips",
		"linux/arm64",
		true,
		false,
		"aws",
		"c6g.2xlarge",
		"${IMAGE_UBUNTU_2204_ARM_64}",
		false,
		false,
	)
	pipeline.AddGroupStep(group, containersFipsArm64)

	// amd64 OTEL containers
	containersOtelAmd64 := containerPackagingStep(
		":package: amd64: OTEL_COMPONENT Containers",
		"packaging-containers-amd64-otel-component",
		"linux/amd64",
		false,
		true,
		"gcp",
		pipeline.MachineTypeN2Standard8,
		"${IMAGE_UBUNTU_2204_X86_64}",
		false,
		true,
	)
	pipeline.AddGroupStep(group, containersOtelAmd64)

	// arm64 OTEL containers
	containersOtelArm64 := containerPackagingStep(
		":package: arm64: OTEL_COMPONENT Containers",
		"packaging-containers-arm64-otel-component",
		"linux/arm64",
		false,
		true,
		"aws",
		"c6g.2xlarge",
		"${IMAGE_UBUNTU_2204_ARM_64}",
		false,
		false,
	)
	pipeline.AddGroupStep(group, containersOtelArm64)

	return group
}

// packagingStep creates a standard packaging step.
func packagingStep(label, key, platforms, packages string, fips, otel bool, provider, machineType, image string, diskSize int, dockerLogin bool) *pipeline.CommandStep {
	step := pipeline.CommandWithKey(label, key, ".buildkite/scripts/steps/integration-package.sh")

	env := map[string]string{
		"PLATFORMS": platforms,
		"PACKAGES":  packages,
	}
	if fips {
		env["FIPS"] = "true"
	}
	if otel {
		env["OTEL_COMPONENT"] = "true"
	}
	pipeline.SetEnv(step, env)

	pipeline.SetArtifactPaths(step, "build/distributions/**")
	pipeline.SetRetryAutomatic(step, 1)

	agent := pipeline.Agent{
		"provider": provider,
		"image":    image,
	}
	if provider == "gcp" {
		agent["machineType"] = machineType
	} else {
		agent["instanceType"] = machineType
	}
	if diskSize > 0 {
		agent["diskSizeGb"] = diskSize
	}
	pipeline.SetAgent(step, agent)

	if dockerLogin {
		pipeline.WithVaultDockerLogin(step)
	}

	return step
}

// containerPackagingStep creates a container packaging step.
func containerPackagingStep(label, key, platforms string, fips, otel bool, provider, machineType, image string, cloudPush, dockerLogin bool) *pipeline.CommandStep {
	var command string
	if cloudPush {
		command = ".buildkite/scripts/steps/integration-package.sh\n.buildkite/scripts/steps/integration-cloud-image-push.sh"
	} else {
		command = ".buildkite/scripts/steps/integration-package.sh"
	}

	step := pipeline.CommandWithKey(label, key, command)

	env := map[string]string{
		"PACKAGES":  "docker",
		"PLATFORMS": platforms,
	}
	if fips {
		env["FIPS"] = "true"
	}
	if otel {
		env["OTEL_COMPONENT"] = "true"
	}
	pipeline.SetEnv(step, env)

	pipeline.SetArtifactPaths(step, "build/distributions/**")

	agent := pipeline.Agent{
		"provider":   provider,
		"image":      image,
		"diskSizeGb": 200,
	}
	if provider == "gcp" {
		agent["machineType"] = machineType
	} else {
		agent["instanceType"] = machineType
	}
	pipeline.SetAgent(step, agent)

	if dockerLogin {
		pipeline.WithVaultDockerLogin(step)
	}

	return step
}

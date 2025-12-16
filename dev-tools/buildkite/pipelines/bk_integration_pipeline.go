// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// K8s test versions to run against.
var (
	k8sMinTestVersion  = "v1.27.16"
	k8sMaxTestVersion  = "v1.34.0"
	k8sAllTestVersions = []string{
		k8sMinTestVersion,
		"v1.28.15",
		"v1.29.14",
		"v1.30.0",
		"v1.31.0",
		"v1.32.0",
		"v1.33.0",
		k8sMaxTestVersion,
	}
)

// BKIntegrationPipeline generates the .buildkite/bk.integration.pipeline.yml pipeline.
// This pipeline runs integration tests for various platforms and configurations.
func BKIntegrationPipeline() *pipeline.Pipeline {
	p := pipeline.New().
		Env("VAULT_PATH", pipeline.VaultPathGCP).
		Env("ASDF_MAGE_VERSION", "1.14.0").
		// Image environment variables - managed by updatecli
		Env("IMAGE_UBUNTU_2404_X86_64", pipeline.ImageUbuntu2404X86).
		Env("IMAGE_UBUNTU_2404_ARM_64", pipeline.ImageUbuntu2404ARM).
		Env("IMAGE_RHEL_8", pipeline.ImageRHEL8).
		Env("IMAGE_RHEL_10", pipeline.ImageRHEL10).
		Env("IMAGE_DEBIAN_11", pipeline.ImageDebian11).
		Env("IMAGE_DEBIAN_13", pipeline.ImageDebian13).
		Env("IMAGE_WIN_2022", pipeline.ImageWin2022).
		Env("IMAGE_WIN_2025", pipeline.ImageWin2025).
		Env("ASDF_TERRAFORM_VERSION", "1.9.2")

	// Custom ECH Testing
	p.Add(echTestingStep())

	// Start ESS stack
	p.Add(essStartStep())

	// Extended runtime leak tests group
	p.Add(extendedLeakTestsGroup())

	// Stateful: Windows group
	p.Add(windowsTestsGroup())

	// Stateful: Ubuntu group
	p.Add(ubuntuTestsGroup())

	// Stateful: Debian group
	p.Add(debianTestsGroup())

	// Stateful: RHEL group
	p.Add(rhelTestsGroup())

	// Kubernetes group
	p.Add(kubernetesTestsGroup())

	// Serverless integration test group
	p.Add(serverlessTestsGroup())

	// ESS stack cleanup
	p.Add(essCleanupStep())

	// Aggregate test reports
	p.Add(aggregateReportsStep())

	return p
}

// echTestingStep creates the Custom ECH Testing step.
func echTestingStep() *pipeline.CommandStep {
	step := pipeline.CommandWithKey("Custom ECH Testing", "integration-tests-ech",
		`#!/usr/bin/env bash
buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step 'packaging-amd64'
.buildkite/scripts/steps/integration_tests_tf.sh ech true`)

	pipeline.SetDependsOn(step, "packaging-containers-amd64", "packaging-containers-arm64")
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE":                           "github.com/elastic/elastic-agent/testing/integration/ess",
		"TF_VAR_integration_server_docker_image": "docker.elastic.co/beats-ci/elastic-agent-cloud:git-${BUILDKITE_COMMIT:0:12}",
		"FORCE_ESS_CREATE":                       "true",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.GCPAgent("${IMAGE_UBUNTU_2404_X86_64}", pipeline.MachineTypeN2Standard8))
	pipeline.WithVaultECKeyProd(step)

	return step
}

// essStartStep creates the Start ESS stack step.
func essStartStep() *pipeline.CommandStep {
	step := pipeline.CommandWithKey("Start ESS stack for integration tests", "integration-ess",
		".buildkite/scripts/steps/ess_start.sh")

	pipeline.SetNotify(step, "buildkite/elastic-agent-extended-testing - ESS stack provision")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetArtifactPaths(step, "test_infra/ess/*.tfstate", "test_infra/ess/*.lock.hcl")
	pipeline.SetAgent(step, pipeline.DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5"))
	pipeline.WithVaultECKeyProd(step)

	return step
}

// extendedLeakTestsGroup creates the Extended runtime leak tests group.
func extendedLeakTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Extended runtime leak tests", "extended-integration-tests")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - Runtime leak tests")
	pipeline.SetGroupDependsOn(group, "integration-ess")

	// Windows:2022:amd64:sudo
	win2022 := leakTestStep("Windows:2022:amd64:sudo", "packaging-amd64",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-windows-x86_64*  . --step 'packaging-amd64'\n.buildkite/scripts/steps/integration_tests_tf.ps1 fleet true",
		"${IMAGE_WIN_2022}")
	pipeline.AddGroupStep(group, win2022)

	// Windows:2025:amd64:sudo
	win2025 := leakTestStep("Windows:2025:amd64:sudo", "packaging-amd64",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-windows-x86_64* . --step 'packaging-amd64'\n.buildkite/scripts/steps/integration_tests_tf.ps1 fleet true",
		"${IMAGE_WIN_2025}")
	pipeline.AddGroupStep(group, win2025)

	// Ubuntu:2404:amd64:sudo
	ubuntu := leakTestStep("Ubuntu:2404:amd64:sudo", "packaging-amd64",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step 'packaging-amd64'\n.buildkite/scripts/steps/integration_tests_tf.sh fleet true",
		"${IMAGE_UBUNTU_2404_X86_64}")
	pipeline.AddGroupStep(group, ubuntu)

	return group
}

// leakTestStep creates a leak test step.
func leakTestStep(label, dependsOn, command, image string) *pipeline.CommandStep {
	step := pipeline.Command(label, command)
	pipeline.SetDependsOn(step, dependsOn)
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/leak",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.GCPAgent(image, pipeline.MachineTypeN2Standard8))
	pipeline.WithVaultECKeyProd(step)

	return step
}

// windowsTestsGroup creates the Stateful: Windows tests group.
func windowsTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Stateful: Windows", "integration-tests-win")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - Windows")
	pipeline.SetGroupDependsOn(group, "integration-ess")

	// Win2022:sudo:{{matrix}}
	win2022Sudo := windowsTestStep("Win2022:sudo:{{matrix}}", "${IMAGE_WIN_2022}", true,
		[]string{"default", "fleet", "fleet-endpoint-security", "fleet-privileged", "standalone-upgrade", "upgrade", "upgrade-flavor", "install-uninstall"})
	pipeline.AddGroupStep(group, win2022Sudo)

	// Win2022:non-sudo:{{matrix}}
	win2022NonSudo := windowsTestStep("Win2022:non-sudo:{{matrix}}", "${IMAGE_WIN_2022}", false,
		[]string{"default"})
	pipeline.AddGroupStep(group, win2022NonSudo)

	// Win2025:sudo:{{matrix}}
	win2025Sudo := windowsTestStep("Win2025:sudo:{{matrix}}", "${IMAGE_WIN_2025}", true,
		[]string{"default", "fleet", "fleet-endpoint-security", "fleet-privileged", "standalone-upgrade", "upgrade", "upgrade-flavor", "install-uninstall"})
	pipeline.AddGroupStep(group, win2025Sudo)

	// Win2025:non-sudo:{{matrix}}
	win2025NonSudo := windowsTestStep("Win2025:non-sudo:{{matrix}}", "${IMAGE_WIN_2025}", false,
		[]string{"default"})
	pipeline.AddGroupStep(group, win2025NonSudo)

	return group
}

// windowsTestStep creates a Windows test step with matrix.
func windowsTestStep(label, image string, sudo bool, matrix []string) *pipeline.CommandStep {
	sudoArg := "false"
	if sudo {
		sudoArg = "true"
	}

	step := pipeline.Command(label,
		"buildkite-agent artifact download build/distributions/elastic-agent-*-windows-x86_64* . --step 'packaging-amd64'\n.buildkite/scripts/steps/integration_tests_tf.ps1 {{matrix}} "+sudoArg)
	pipeline.SetDependsOn(step, "packaging-amd64")
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetAgent(step, pipeline.GCPAgent(image, pipeline.MachineTypeN2Standard8))
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetSimpleMatrix(step, matrix)

	return step
}

// ubuntuTestsGroup creates the Stateful: Ubuntu tests group.
func ubuntuTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Stateful:Ubuntu", "integration-tests-ubuntu")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - Ubuntu")
	pipeline.SetGroupDependsOn(group, "integration-ess")

	// x86_64:non-sudo: {{matrix}}
	x86NonSudo := ubuntuTestStep("x86_64:non-sudo: {{matrix}}", "packaging-amd64", false,
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step 'packaging-amd64'\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix}} false",
		pipeline.GCPAgent("${IMAGE_UBUNTU_2404_X86_64}", pipeline.MachineTypeN2Standard8),
		[]string{"default"})
	pipeline.AddGroupStep(group, x86NonSudo)

	// x86_64:sudo: {{matrix}}
	x86Sudo := ubuntuTestStep("x86_64:sudo: {{matrix}}", "packaging-amd64", true,
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step packaging-amd64\nbuildkite-agent artifact download build/distributions/elastic-agent-*-amd64.deb* . --step packaging-amd64\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix}} true",
		pipeline.GCPAgent("${IMAGE_UBUNTU_2404_X86_64}", pipeline.MachineTypeN2Standard8),
		[]string{"default", "upgrade", "upgrade-flavor", "standalone-upgrade", "fleet", "fleet-endpoint-security", "fleet-airgapped", "fleet-airgapped-privileged", "fleet-privileged", "fleet-upgrade-to-pr-build", "install-uninstall", "fqdn", "deb", "container"})
	pipeline.AddGroupStep(group, x86Sudo)

	// arm:sudo: {{matrix}}
	armSudo := ubuntuArmTestStep("arm:sudo: {{matrix}}", "packaging-arm64",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-arm64* . --step 'packaging-arm64'\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix}} true",
		[]string{"default", "upgrade", "upgrade-flavor", "standalone-upgrade", "fleet"})
	pipeline.AddGroupStep(group, armSudo)

	// arm:non-sudo: {{matrix}} (skipped)
	armNonSudo := ubuntuArmNonSudoTestStep()
	pipeline.AddGroupStep(group, armNonSudo)

	return group
}

// ubuntuTestStep creates an Ubuntu test step with matrix.
func ubuntuTestStep(label, dependsOn string, _ bool, command string, agent pipeline.Agent, matrix []string) *pipeline.CommandStep {
	step := pipeline.Command(label, command)
	pipeline.SetDependsOn(step, dependsOn)
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, agent)
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetSimpleMatrix(step, matrix)

	return step
}

// ubuntuArmTestStep creates an ARM Ubuntu test step with matrix.
func ubuntuArmTestStep(label, dependsOn, command string, matrix []string) *pipeline.CommandStep {
	step := pipeline.Command(label, command)
	pipeline.SetDependsOn(step, dependsOn)
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetAgent(step, pipeline.AWSAgent("${IMAGE_UBUNTU_2404_ARM_64}", "m6g.2xlarge"))
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetSimpleMatrix(step, matrix)

	return step
}

// ubuntuArmNonSudoTestStep creates the skipped ARM non-sudo test step.
func ubuntuArmNonSudoTestStep() *pipeline.CommandStep {
	step := pipeline.Command("arm:non-sudo: {{matrix}}",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-arm64* . --step 'packaging-arm64'\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix}} false")
	pipeline.SetSkip(step, true)
	pipeline.SetDependsOn(step, "packaging-arm64")
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.AWSAgent("${IMAGE_UBUNTU_2404_ARM_64}", "m6g.xlarge"))
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetSimpleMatrix(step, []string{"default"})

	return step
}

// debianTestsGroup creates the Stateful: Debian tests group.
func debianTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Stateful:Debian", "integration-tests-debian")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - Debian")
	pipeline.SetGroupDependsOn(group, "integration-ess")

	// x86_64:non-sudo: {{matrix.group}} - {{matrix.image}}
	nonSudo := debianTestStep("x86_64:non-sudo: {{matrix.group}} - {{matrix.image}}", "packaging-amd64",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step 'packaging-amd64'\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix.group}} false",
		[]string{"${IMAGE_DEBIAN_11}", "${IMAGE_DEBIAN_13}"},
		[]string{"default"})
	pipeline.AddGroupStep(group, nonSudo)

	// x86_64:sudo: {{matrix.group}} - {{matrix.image}}
	sudo := debianTestStep("x86_64:sudo: {{matrix.group}} - {{matrix.image}}", "packaging-amd64",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step packaging-amd64\nbuildkite-agent artifact download build/distributions/elastic-agent-*-amd64.deb* . --step packaging-amd64\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix.group}} true",
		[]string{"${IMAGE_DEBIAN_11}", "${IMAGE_DEBIAN_13}"},
		[]string{"default", "upgrade", "upgrade-flavor", "standalone-upgrade", "fleet", "fleet-endpoint-security", "fleet-airgapped", "fleet-airgapped-privileged", "fleet-privileged", "fleet-upgrade-to-pr-build", "install-uninstall", "deb", "container"})
	pipeline.AddGroupStep(group, sudo)

	return group
}

// debianTestStep creates a Debian test step with setup matrix.
func debianTestStep(label, dependsOn, command string, images, groups []string) *pipeline.CommandStep {
	step := pipeline.Command(label, command)
	pipeline.SetDependsOn(step, dependsOn)
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.Agent{
		"provider":    "gcp",
		"machineType": pipeline.MachineTypeN2Standard8,
		"image":       "{{matrix.image}}",
	})
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetMatrix(step, map[string][]string{
		"image": images,
		"group": groups,
	})

	return step
}

// rhelTestsGroup creates the Stateful: RHEL tests group.
func rhelTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Stateful:RHEL", "integration-tests-rhel")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - RHEL")
	pipeline.SetGroupDependsOn(group, "integration-ess")

	// x86_64:sudo:rpm - {{matrix.image}}
	rpm := rhelTestStep()
	pipeline.AddGroupStep(group, rpm)

	return group
}

// rhelTestStep creates the RHEL RPM test step.
func rhelTestStep() *pipeline.CommandStep {
	step := pipeline.Command("x86_64:sudo:rpm - {{matrix.image}}",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-x86_64.rpm* . --step packaging-amd64\n.buildkite/scripts/steps/integration_tests_tf.sh rpm true")
	pipeline.SetDependsOn(step, "packaging-amd64")
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetAgent(step, pipeline.Agent{
		"provider":    "gcp",
		"machineType": pipeline.MachineTypeN2Standard8,
		"image":       "{{matrix.image}}",
	})
	pipeline.SetMatrix(step, map[string][]string{
		"image": {"${IMAGE_RHEL_8}", "${IMAGE_RHEL_10}"},
	})

	return step
}

// kubernetesTestsGroup creates the Kubernetes tests group.
func kubernetesTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey(":kubernetes: Kubernetes", "integration-tests-kubernetes")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - Kubernetes")
	pipeline.SetGroupDependsOn(group, "integration-ess", "packaging-containers-amd64")

	// Non-PR builds: all k8s versions with grouped variants
	fullK8s := k8sTestStep(":git: :kubernetes: {{matrix.version}}:amd64:{{matrix.variants}}",
		`build.pull_request.id == null`,
		k8sAllTestVersions,
		[]string{
			"basic,slim,complete,service,elastic-otel-collector",
			"wolfi,slim-wolfi,complete-wolfi,elastic-otel-collector-wolfi",
		})
	pipeline.AddGroupStep(group, fullK8s)

	// PR builds: only min/max versions with individual variants
	prK8s := k8sTestStep(":open-pull-request: :kubernetes: {{matrix.version}}:amd64:{{matrix.variants}}",
		`build.pull_request.id != null`,
		[]string{k8sMinTestVersion, k8sMaxTestVersion},
		[]string{"basic", "slim", "complete", "service", "elastic-otel-collector", "wolfi", "slim-wolfi", "complete-wolfi", "elastic-otel-collector-wolfi"})
	pipeline.AddGroupStep(group, prK8s)

	return group
}

// k8sTestStep creates a Kubernetes test step with matrix.
func k8sTestStep(label, condition string, versions, variants []string) *pipeline.CommandStep {
	step := pipeline.Command(label,
		`buildkite-agent artifact download build/distributions/*-linux-amd64.docker.tar.gz . --step 'packaging-containers-amd64'
.buildkite/scripts/steps/integration_tests_tf.sh kubernetes false`)

	pipeline.SetIf(step, condition)
	pipeline.SetEnv(step, map[string]string{
		"K8S_VERSION":       "{{matrix.version}}",
		"ASDF_KIND_VERSION": "0.27.0",
		"DOCKER_VARIANTS":   "{{matrix.variants}}",
		"TARGET_ARCH":       "amd64",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**", "build/*.pod_logs_dump/*")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.GCPAgentWithDisk("${IMAGE_UBUNTU_2404_X86_64}", pipeline.MachineTypeN2Standard8, 80, ""))
	pipeline.WithVaultECKeyProd(step)
	pipeline.SetMatrix(step, map[string][]string{
		"variants": variants,
		"version":  versions,
	})

	return step
}

// serverlessTestsGroup creates the Serverless integration tests group.
func serverlessTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Serverless integration test", "integration-tests-serverless")
	pipeline.SetGroupNotify(group, "buildkite/elastic-agent-extended-testing - Serverless integration test")

	// Windows:2022:amd64:sudo
	win2022 := serverlessWindowsTestStep("Windows:2022:amd64:sudo", "${IMAGE_WIN_2022}")
	pipeline.AddGroupStep(group, win2022)

	// Windows:2025:amd64:sudo
	win2025 := serverlessWindowsTestStep("Windows:2025:amd64:sudo", "${IMAGE_WIN_2025}")
	pipeline.AddGroupStep(group, win2025)

	// Ubuntu:2404:amd64:sudo
	ubuntu := serverlessUbuntuTestStep()
	pipeline.AddGroupStep(group, ubuntu)

	return group
}

// serverlessWindowsTestStep creates a serverless Windows test step.
func serverlessWindowsTestStep(label, image string) *pipeline.CommandStep {
	step := pipeline.Command(label,
		"buildkite-agent artifact download build/distributions/elastic-agent-*-windows-x86_64* . --step 'packaging-amd64'\n.buildkite/scripts/buildkite-integration-tests.ps1 fleet true")
	pipeline.SetDependsOn(step, "packaging-amd64")
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/serverless",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.GCPAgent(image, pipeline.MachineTypeN2Standard8))
	pipeline.WithGoogleOIDC(step)
	pipeline.WithGCPSecretManagerServerless(step)

	return step
}

// serverlessUbuntuTestStep creates the serverless Ubuntu test step.
func serverlessUbuntuTestStep() *pipeline.CommandStep {
	step := pipeline.Command("Ubuntu:2404:amd64:sudo",
		"buildkite-agent artifact download build/distributions/elastic-agent-*-linux-x86_64* . --step 'packaging-amd64'\nsudo -E .buildkite/scripts/buildkite-integration-tests.sh fleet true")
	pipeline.SetDependsOn(step, "packaging-amd64")
	pipeline.SetEnv(step, map[string]string{
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/serverless",
	})
	pipeline.SetArtifactPaths(step, "build/*", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.GCPAgent("${IMAGE_UBUNTU_2404_X86_64}", pipeline.MachineTypeN2Standard8))
	pipeline.WithGoogleOIDC(step)
	pipeline.WithGCPSecretManagerServerless(step)

	return step
}

// essCleanupStep creates the ESS stack cleanup step.
func essCleanupStep() *pipeline.CommandStep {
	step := pipeline.Command("ESS stack cleanup",
		`buildkite-agent artifact download "test_infra/ess/**" . --step "integration-ess"
ls -lah test_infra/ess
.buildkite/scripts/steps/ess_down.sh`)

	pipeline.SetDependsOn(step,
		"integration-tests-ubuntu",
		"integration-tests-win",
		"integration-tests-rhel",
		"integration-tests-kubernetes",
		"extended-integration-tests",
		"integration-tests-debian")
	pipeline.SetAllowDependencyFailure(step, true)
	pipeline.SetAgent(step, pipeline.DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5"))
	pipeline.WithVaultECKeyProd(step)

	return step
}

// aggregateReportsStep creates the Aggregate test reports step.
func aggregateReportsStep() *pipeline.CommandStep {
	step := pipeline.CommandWithKey("Aggregate test reports", "aggregate-reports",
		`buildkite-agent artifact download "build/*.xml" .
buildkite-agent artifact download "build\*.xml" .`)

	pipeline.SetDependsOn(step,
		"integration-tests-ech",
		"integration-tests-ubuntu",
		"integration-tests-win",
		"integration-tests-rhel",
		"integration-tests-kubernetes",
		"integration-tests-serverless",
		"integration-tests-debian")
	pipeline.SetAllowDependencyFailure(step, true)
	pipeline.SetAgent(step, pipeline.DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5"))
	pipeline.SetSoftFailExitStatus(step, "*")
	pipeline.WithVaultBuildkiteAnalytics(step)
	pipeline.WithTestCollector(step, "build/*.xml", "junit")

	return step
}

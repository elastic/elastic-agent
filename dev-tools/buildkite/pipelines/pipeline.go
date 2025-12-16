// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// Pipeline generates the main .buildkite/pipeline.yml pipeline.
// This is the primary CI pipeline for elastic-agent including unit tests,
// K8s tests, and various triggers.
func Pipeline() *pipeline.Pipeline {
	p := pipeline.New().
		Env("VAULT_PATH", pipeline.VaultPathGCP).
		Env("IMAGE_UBUNTU_2204_X86_64", pipeline.ImageUbuntu2204X86).
		Env("IMAGE_UBUNTU_2204_ARM_64", pipeline.ImageUbuntu2204ARM).
		Env("IMAGE_WIN_2016", pipeline.ImageWin2016).
		Env("IMAGE_WIN_2022", pipeline.ImageWin2022).
		Env("IMAGE_WIN_10", pipeline.ImageWin10).
		Env("IMAGE_WIN_11", pipeline.ImageWin11)

	// check-ci step
	checkCI := pipeline.CommandWithKey("check-ci", "check-ci", ".buildkite/scripts/steps/check-ci.sh")
	pipeline.SetAgent(checkCI, pipeline.Agent{
		"provider": "gcp",
		"image":    "${IMAGE_UBUNTU_2204_X86_64}",
	})
	pipeline.SetRetryManual(checkCI)
	p.Add(checkCI)

	// Unit tests group
	p.Add(unitTestsGroup())

	// macOS tests group
	p.Add(macOSTestsGroup())

	// Desktop Windows tests group
	p.Add(desktopWindowsTestsGroup())

	// Junit annotate step
	p.Add(junitAnnotateStep())

	// K8s tests group
	p.Add(k8sTestsGroup())

	// Trigger k8s sync
	p.Add(triggerK8sSync())

	// Trigger Extended tests for Pull request
	p.Add(triggerExtendedTestsPR())

	// Trigger Extended tests for branches
	p.Add(triggerExtendedTestsBranch())

	// Trigger Serverless Beats Tests
	p.Add(triggerServerlessBeatsTests())

	// Trigger Elastic Agent Package
	p.Add(triggerElasticAgentPackage())

	// DRY RUN publish to serverless
	p.Add(triggerDryRunServerless())

	// wait for CI to be done
	p.Wait()

	// Publish to serverless
	p.Add(triggerPublishServerless())

	return p
}

// unitTestsGroup creates the "Unit tests" group with all unit test steps.
func unitTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Unit tests", "unit-tests")

	// Unit tests - Ubuntu 22.04
	ubuntu2204 := pipeline.CommandWithKey("Unit tests - Ubuntu 22.04", "unit-tests-2204", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetArtifactPaths(ubuntu2204, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(ubuntu2204, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_UBUNTU_2204_X86_64}",
		"machineType": pipeline.MachineTypeN2Standard8,
	})
	pipeline.SetRetry(ubuntu2204, 1, true)
	pipeline.AddGroupStep(group, ubuntu2204)

	// Unit tests - Ubuntu 22.04 with requirefips build tag
	ubuntu2204Fips := pipeline.CommandWithKey("Unit tests - Ubuntu 22.04 with requirefips build tag", "unit-tests-2204-fips-tag", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.AddEnv(ubuntu2204Fips, "FIPS", "true")
	pipeline.SetArtifactPaths(ubuntu2204Fips, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(ubuntu2204Fips, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_UBUNTU_2204_X86_64}",
		"machineType": pipeline.MachineTypeN2Standard8,
	})
	pipeline.SetRetry(ubuntu2204Fips, 1, true)
	pipeline.AddGroupStep(group, ubuntu2204Fips)

	// Unit tests - fips140=only Ubuntu 22.04
	ubuntu2204Fips140 := pipeline.CommandWithKey("Unit tests - fips140=only Ubuntu 22.04", "unit-tests-2204-fips140-only", `GODEBUG="fips140=only" .buildkite/scripts/steps/unit-tests.sh`)
	pipeline.AddEnv(ubuntu2204Fips140, "FIPS", "true")
	pipeline.SetArtifactPaths(ubuntu2204Fips140, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(ubuntu2204Fips140, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_UBUNTU_2204_X86_64}",
		"machineType": pipeline.MachineTypeN2Standard8,
	})
	pipeline.SetRetry(ubuntu2204Fips140, 1, true)
	pipeline.AddGroupStep(group, ubuntu2204Fips140)

	// Unit tests - Ubuntu 22.04 ARM64
	ubuntu2204ARM := pipeline.CommandWithKey("Unit tests - Ubuntu 22.04 ARM64", "unit-tests-2204-arm64", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetArtifactPaths(ubuntu2204ARM, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(ubuntu2204ARM, pipeline.Agent{
		"provider":     "aws",
		"image":        "${IMAGE_UBUNTU_2204_ARM_64}",
		"diskSizeGb":   200,
		"instanceType": pipeline.InstanceTypeM6gXLarge,
	})
	pipeline.SetRetry(ubuntu2204ARM, 1, true)
	pipeline.AddGroupStep(group, ubuntu2204ARM)

	// Unit tests - Windows 2022
	win2022 := pipeline.CommandWithKey("Unit tests - Windows 2022", "unit-tests-win2022", ".buildkite/scripts/steps/unit-tests.ps1")
	pipeline.SetArtifactPaths(win2022, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(win2022, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_WIN_2022}",
		"machineType": pipeline.MachineTypeN2Standard8,
		"disk_size":   200,
		"disk_type":   "pd-ssd",
	})
	pipeline.SetRetry(win2022, 1, true)
	pipeline.AddGroupStep(group, win2022)

	// Unit tests - Windows 2016
	win2016 := pipeline.CommandWithKey("Unit tests - Windows 2016", "unit-tests-win2016", ".buildkite/scripts/steps/unit-tests.ps1")
	pipeline.SetArtifactPaths(win2016, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(win2016, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_WIN_2016}",
		"machineType": pipeline.MachineTypeN2Standard8,
		"disk_size":   200,
		"disk_type":   "pd-ssd",
	})
	pipeline.SetRetry(win2016, 1, true)
	pipeline.AddGroupStep(group, win2016)

	return group
}

// macOSTestsGroup creates the "macOS tests" group.
func macOSTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("macOS tests", "macos-unit-tests")

	// Unit tests - macOS 15 ARM
	macOS15 := pipeline.Command("Unit tests - macOS 15 ARM", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetArtifactPaths(macOS15, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(macOS15, pipeline.Agent{
		"provider":    "orka",
		"imagePrefix": "generic-base-15-arm-002",
	})
	pipeline.SetRetry(macOS15, 1, true)
	pipeline.AddGroupStep(group, macOS15)

	// Unit tests - macOS 13 (main and release branches only)
	macOS13 := pipeline.Command("Unit tests - macOS 13", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetBranches(macOS13, "main 8.* 9.*")
	pipeline.SetArtifactPaths(macOS13, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(macOS13, pipeline.Agent{
		"provider":    "orka",
		"imagePrefix": "generic-13-ventura-x64",
	})
	pipeline.SetRetry(macOS13, 1, true)
	pipeline.AddGroupStep(group, macOS13)

	return group
}

// desktopWindowsTestsGroup creates the "Desktop Windows tests" group.
func desktopWindowsTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("Desktop Windows tests", "extended-windows")

	// Unit tests - Windows 10
	win10 := pipeline.CommandWithKey("Unit tests - Windows 10", "unit-tests-win10", ".buildkite/scripts/steps/unit-tests.ps1")
	pipeline.SetArtifactPaths(win10, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(win10, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_WIN_10}",
		"machineType": pipeline.MachineTypeN2Standard8,
		"disk_type":   "pd-ssd",
	})
	pipeline.SetRetry(win10, 1, true)
	pipeline.AddGroupStep(group, win10)

	// Unit tests - Windows 11
	win11 := pipeline.CommandWithKey("Unit tests - Windows 11", "unit-tests-win11", ".buildkite/scripts/steps/unit-tests.ps1")
	pipeline.SetArtifactPaths(win11, "build/TEST-*.html", "build/TEST-*.xml", "build/diagnostics/*", "coverage-*.out")
	pipeline.SetAgent(win11, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_WIN_11}",
		"machineType": pipeline.MachineTypeN2Standard8,
		"disk_type":   "pd-ssd",
	})
	pipeline.SetRetry(win11, 1, true)
	pipeline.AddGroupStep(group, win11)

	return group
}

// junitAnnotateStep creates the junit annotate step with dependencies.
func junitAnnotateStep() *pipeline.CommandStep {
	step := &pipeline.CommandStep{
		Label: pipeline.Ptr(":junit: Junit annotate"),
	}
	pipeline.SetAgent(step, pipeline.Agent{
		"image": "docker.elastic.co/ci-agent-images/buildkite-junit-annotate:1.0",
	})
	pipeline.AddPlugin(step, "junit-annotate#v2.7.0", map[string]any{
		"artifacts":       "**TEST-*.xml",
		"always-annotate": true,
		"run-in-docker":   false,
	})
	pipeline.SetDependsOnWithFailure(step,
		pipeline.DependsOnDep{Step: "unit-tests-2204", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-2204-fips-tag", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-2204-fips140-only", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-2204-arm64", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-win2022", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-win2016", AllowFailure: true},
		pipeline.DependsOnDep{Step: "macos-unit-tests", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-win10", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-win11", AllowFailure: true},
	)
	return step
}

// k8sTestsGroup creates the "K8s tests" group with matrix.
func k8sTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("K8s tests", "k8s-tests")

	step := pipeline.Command("K8s tests: {{matrix.k8s_version}}", ".buildkite/scripts/steps/k8s-tests.sh")
	pipeline.SetEnv(step, map[string]string{
		"K8S_VERSION":  "v{{matrix.k8s_version}}",
		"KIND_VERSION": "v0.27.0",
	})
	pipeline.SetAgent(step, pipeline.Agent{
		"provider": "gcp",
		"image":    "${IMAGE_UBUNTU_2204_X86_64}",
	})
	pipeline.SetMatrix(step, map[string][]string{
		"k8s_version": {"1.33.0", "1.32.0", "1.31.0", "1.30.0", "1.29.4", "1.28.9"},
	})
	pipeline.SetRetryManual(step)
	pipeline.AddGroupStep(group, step)

	return group
}

// triggerK8sSync creates the trigger for k8s sync.
func triggerK8sSync() *pipeline.CommandStep {
	step := pipeline.Command("Trigger k8s sync", ".buildkite/scripts/steps/sync-k8s.sh")
	pipeline.SetBranches(step, "main")
	pipeline.SetAgent(step, pipeline.Agent{
		"provider": "gcp",
		"image":    "${IMAGE_UBUNTU_2204_X86_64}",
	})
	pipeline.AddEnv(step, "GH_VERSION", "2.4.0")
	pipeline.SetIfChanged(step,
		"deploy/kubernetes/*",
		"version/docs/version.asciidoc",
	)
	return step
}

// triggerExtendedTestsPR creates the trigger for extended tests on PRs.
func triggerExtendedTestsPR() *pipeline.CommandStep {
	step := pipeline.Command("Trigger Extended tests for Pull request", "buildkite-agent pipeline upload .buildkite/integration.pipeline.yml")
	pipeline.SetIf(step, `(build.pull_request.id != null && !build.env("GITHUB_PR_LABELS") =~ /skip-it/) ||
build.env("GITHUB_PR_TRIGGER_COMMENT") =~ /.*extended.*/`)
	pipeline.SetEnv(step, map[string]string{
		"BUILDKITE_PULL_REQUEST":             "${BUILDKITE_PULL_REQUEST}",
		"BUILDKITE_PULL_REQUEST_BASE_BRANCH": "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}",
		"GITHUB_PR_LABELS":                   "${GITHUB_PR_LABELS}",
	})
	pipeline.SetIfChanged(step,
		"internal/**",
		"dev-tools/**",
		"pkg/**",
		"deploy/**",
		"test_infra/**",
		"testing/**",
		"version/**",
		"specs/**",
		".agent-versions.json",
		".go-version",
		".package-version",
		"go.mod",
		"go.sum",
		"magefile.go",
		"main.go",
		".buildkite/integration.pipeline.yml",
		".buildkite/bk.integration.pipeline.yml",
		".buildkite/bk.integration-fips.pipeline.yml",
		".buildkite/pipeline.yml",
		".buildkite/scripts/**",
		".buildkite/hooks/**",
	)
	return step
}

// triggerExtendedTestsBranch creates the trigger for extended tests on branches.
func triggerExtendedTestsBranch() *pipeline.TriggerStep {
	trigger := pipeline.Trigger("Triggering Extended tests for branches", "elastic-agent-extended-testing")
	pipeline.SetTriggerIf(trigger, "build.pull_request.id == null")
	pipeline.SetTriggerBuild(trigger, "${BUILDKITE_COMMIT}", "${BUILDKITE_BRANCH}", nil)
	return trigger
}

// triggerServerlessBeatsTests creates the trigger for serverless beats tests.
func triggerServerlessBeatsTests() *pipeline.TriggerStep {
	trigger := pipeline.Trigger("Trigger Serverless Beats Tests", "beats-agent-serverless-tests")
	pipeline.SetTriggerIf(trigger, "build.pull_request.id != null")
	pipeline.SetTriggerBuild(trigger, "${BUILDKITE_COMMIT}", "${BUILDKITE_BRANCH}", nil)
	pipeline.SetTriggerIfChanged(trigger,
		".buildkite/serverless.beats.tests.yml",
		".buildkite/scripts/steps/beats_tests.sh",
		".buildkite/hooks/pre-command",
	)
	return trigger
}

// triggerElasticAgentPackage creates the trigger for elastic agent package.
func triggerElasticAgentPackage() *pipeline.CommandStep {
	step := &pipeline.CommandStep{
		Label: pipeline.Ptr("Trigger Elastic Agent Package"),
	}
	pipeline.SetIf(step, "build.pull_request.id != null")
	pipeline.SetCommands(step,
		".buildkite/scripts/steps/trigger-elastic-agent-package.sh",
		".buildkite/scripts/steps/trigger-elastic-agent-package.sh | buildkite-agent pipeline upload",
	)
	pipeline.SetIfChanged(step,
		".buildkite/pipeline.elastic-agent-package.yml",
		".buildkite/scripts/steps/package.sh",
		".buildkite/scripts/steps/trigger-elastic-agent-package.sh",
		"magefile.go",
		"dev-tools/**/*",
	)
	return step
}

// triggerDryRunServerless creates the DRY RUN publish to serverless trigger.
func triggerDryRunServerless() *pipeline.TriggerStep {
	trigger := pipeline.Trigger("DRY RUN publish to serverless", "agentless-serverless-release")
	pipeline.SetTriggerIf(trigger, `build.pull_request.id != null && build.env("BUILDKITE_PULL_REQUEST_BASE_BRANCH") == "main"`)
	pipeline.SetTriggerIfChanged(trigger,
		".buildkite/pipeline.yml",
		".buildkite/pipeline.agentless-app-release.yaml",
		".buildkite/scripts/steps/ecp-internal-release.sh",
		".buildkite/scripts/steps/integration-package.sh",
		".buildkite/scripts/steps/validate-agentless-docker-image.sh",
	)
	pipeline.SetTriggerBuildWithMessage(trigger,
		"${BUILDKITE_COMMIT}",
		"${BUILDKITE_BRANCH}",
		"publish to serverless (dry-run) #${BUILDKITE_PULL_REQUEST}",
		map[string]string{"DRY_RUN": "true"},
	)
	return trigger
}

// triggerPublishServerless creates the publish to serverless trigger.
func triggerPublishServerless() *pipeline.TriggerStep {
	trigger := pipeline.Trigger("Publish to serverless", "agentless-serverless-release")
	pipeline.SetTriggerBranches(trigger, "main")
	pipeline.SetTriggerBuild(trigger, "${BUILDKITE_COMMIT}", "", nil)
	return trigger
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline_test

import (
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// TestGeneratePipeline generates a pipeline similar to .buildkite/pipeline.yml
// and compares it against a known fixture file.
func TestGeneratePipeline(t *testing.T) {
	p := generateExamplePipeline()

	result, err := pipeline.CompareWithFile(p, "testdata/example_pipeline.yml")
	if err != nil {
		t.Fatalf("failed to compare pipeline: %v", err)
	}

	if !result.Equal {
		t.Errorf("generated pipeline does not match expected:\n%s", result.Diff)
	}
}

// TestGeneratePipelineYAML verifies the pipeline can be marshaled to YAML without error.
func TestGeneratePipelineYAML(t *testing.T) {
	p := generateExamplePipeline()

	yaml, err := p.MarshalYAML()
	if err != nil {
		t.Fatalf("failed to marshal pipeline: %v", err)
	}

	if len(yaml) == 0 {
		t.Error("expected non-empty YAML output")
	}
}

// generateExamplePipeline creates a pipeline demonstrating all major features.
// This generates a pipeline similar to .buildkite/pipeline.yml
func generateExamplePipeline() *pipeline.Pipeline {
	// Common artifact paths for test steps
	testArtifacts := []string{
		"build/TEST-*.html",
		"build/TEST-*.xml",
		"build/diagnostics/*",
		"coverage-*.out",
	}

	// check-ci step
	checkCIStep := pipeline.CommandWithKey("check-ci", "check-ci", ".buildkite/scripts/steps/check-ci.sh")
	pipeline.SetAgent(checkCIStep, pipeline.Agent{
		"provider": "gcp",
		"image":    "${IMAGE_UBUNTU_2204_X86_64}",
	})
	pipeline.SetRetryManual(checkCIStep)

	// Build the unit tests group
	unitTestsGroup := pipeline.GroupWithKey("Unit tests", "unit-tests")

	// Add Ubuntu 22.04 unit tests
	ubuntuStep := pipeline.CommandWithKey("Unit tests - Ubuntu 22.04", "unit-tests-2204", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetAgent(ubuntuStep, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_UBUNTU_2204_X86_64}",
		"machineType": pipeline.MachineTypeN2Standard8,
	})
	pipeline.SetArtifactPaths(ubuntuStep, testArtifacts...)
	pipeline.SetRetry(ubuntuStep, 1, true)
	pipeline.AddGroupStep(unitTestsGroup, ubuntuStep)

	// Add Ubuntu 22.04 FIPS unit tests
	fipsStep := pipeline.CommandWithKey("Unit tests - Ubuntu 22.04 with requirefips build tag", "unit-tests-2204-fips-tag", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetAgent(fipsStep, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_UBUNTU_2204_X86_64}",
		"machineType": pipeline.MachineTypeN2Standard8,
	})
	pipeline.AddEnv(fipsStep, "FIPS", "true")
	pipeline.SetArtifactPaths(fipsStep, testArtifacts...)
	pipeline.SetRetry(fipsStep, 1, true)
	pipeline.AddGroupStep(unitTestsGroup, fipsStep)

	// Add Ubuntu 22.04 ARM unit tests
	armStep := pipeline.CommandWithKey("Unit tests - Ubuntu 22.04 ARM64", "unit-tests-2204-arm64", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetAgent(armStep, pipeline.Agent{
		"provider":     "aws",
		"image":        "${IMAGE_UBUNTU_2204_ARM_64}",
		"instanceType": pipeline.InstanceTypeM6gXLarge,
		"diskSizeGb":   200,
	})
	pipeline.SetArtifactPaths(armStep, testArtifacts...)
	pipeline.SetRetry(armStep, 1, true)
	pipeline.AddGroupStep(unitTestsGroup, armStep)

	// Add Windows 2022 unit tests
	winStep := pipeline.CommandWithKey("Unit tests - Windows 2022", "unit-tests-win2022", ".buildkite/scripts/steps/unit-tests.ps1")
	pipeline.SetAgent(winStep, pipeline.Agent{
		"provider":    "gcp",
		"image":       "${IMAGE_WIN_2022}",
		"machineType": pipeline.MachineTypeN2Standard8,
		"disk_size":   200,
		"disk_type":   "pd-ssd",
	})
	pipeline.SetArtifactPaths(winStep, testArtifacts...)
	pipeline.SetRetry(winStep, 1, true)
	pipeline.AddGroupStep(unitTestsGroup, winStep)

	// Build the macOS tests group
	macOSGroup := pipeline.GroupWithKey("macOS tests", "macos-unit-tests")

	macArmStep := pipeline.Command("Unit tests - macOS 15 ARM", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetAgent(macArmStep, pipeline.AgentMacOS15ARM)
	pipeline.SetArtifactPaths(macArmStep, testArtifacts...)
	pipeline.SetRetry(macArmStep, 1, true)
	pipeline.AddGroupStep(macOSGroup, macArmStep)

	macX86Step := pipeline.Command("Unit tests - macOS 13", ".buildkite/scripts/steps/unit-tests.sh")
	pipeline.SetAgent(macX86Step, pipeline.AgentMacOS13X86)
	pipeline.SetBranches(macX86Step, "main 8.* 9.*")
	pipeline.SetArtifactPaths(macX86Step, testArtifacts...)
	pipeline.SetRetry(macX86Step, 1, true)
	pipeline.AddGroupStep(macOSGroup, macX86Step)

	// Build the JUnit annotate step
	junitStep := pipeline.Command(":junit: Junit annotate", "")
	pipeline.SetAgent(junitStep, pipeline.JunitAnnotateAgent())
	pipeline.WithJunitAnnotate(junitStep, "**TEST-*.xml")
	pipeline.SetDependsOnWithFailure(junitStep,
		pipeline.DependsOnDep{Step: "unit-tests-2204", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-2204-fips-tag", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-2204-arm64", AllowFailure: true},
		pipeline.DependsOnDep{Step: "unit-tests-win2022", AllowFailure: true},
		pipeline.DependsOnDep{Step: "macos-unit-tests", AllowFailure: true},
	)

	// Build the K8s tests group with matrix
	k8sGroup := pipeline.GroupWithKey("K8s tests", "k8s-tests")

	k8sStep := pipeline.Command("K8s tests: {{matrix.k8s_version}}", ".buildkite/scripts/steps/k8s-tests.sh")
	pipeline.SetEnv(k8sStep, map[string]string{
		"K8S_VERSION":  "v{{matrix.k8s_version}}",
		"KIND_VERSION": "v0.27.0",
	})
	pipeline.SetAgent(k8sStep, pipeline.Agent{
		"provider": "gcp",
		"image":    "${IMAGE_UBUNTU_2204_X86_64}",
	})
	pipeline.SetMatrix(k8sStep, map[string][]string{
		"k8s_version": {"1.33.0", "1.32.0", "1.31.0", "1.30.0", "1.29.4", "1.28.9"},
	})
	pipeline.SetRetryManual(k8sStep)
	pipeline.AddGroupStep(k8sGroup, k8sStep)

	// Trigger extended tests
	extendedTrigger := pipeline.Trigger("Triggering Extended tests for branches", "elastic-agent-extended-testing")
	pipeline.SetTriggerIf(extendedTrigger, "build.pull_request.id == null")
	pipeline.SetTriggerBuild(extendedTrigger, "${BUILDKITE_COMMIT}", "${BUILDKITE_BRANCH}", nil)

	// Publish to serverless trigger
	serverlessTrigger := pipeline.Trigger("Publish to serverless", "agentless-serverless-release")
	pipeline.SetTriggerBranches(serverlessTrigger, "main")
	pipeline.SetTriggerBuild(serverlessTrigger, "${BUILDKITE_COMMIT}", "", nil)

	// Build the complete pipeline
	p := pipeline.New().
		Env("VAULT_PATH", pipeline.VaultPathGCP).
		Env("IMAGE_UBUNTU_2204_X86_64", pipeline.ImageUbuntu2204X86).
		Env("IMAGE_UBUNTU_2204_ARM_64", pipeline.ImageUbuntu2204ARM).
		Env("IMAGE_WIN_2022", pipeline.ImageWin2022).
		Add(checkCIStep).
		Add(unitTestsGroup).
		Add(macOSGroup).
		Add(junitStep).
		Add(k8sGroup).
		Add(extendedTrigger).
		Wait().
		Add(serverlessTrigger)

	return p
}

// Example_pipeline demonstrates generating a pipeline programmatically.
func Example_pipeline() {
	p := generateExamplePipeline()

	yaml, err := p.MarshalYAML()
	if err != nil {
		panic(err)
	}

	// The generated YAML can be written to a file
	_ = yaml

	// To write to a file:
	// p.WriteYAML(".buildkite/pipeline.yml")

	fmt.Println("Pipeline generated successfully")
	// Output: Pipeline generated successfully
}

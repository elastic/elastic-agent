// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// fipsCommonEnv returns the common FIPS environment variables.
func fipsCommonEnv() map[string]string {
	return map[string]string{
		"FIPS":                                   "true",
		"EC_ENDPOINT":                            "https://api.staging.elastic-gov.com",
		"ESS_REGION":                             "us-gov-east-1",
		"TF_VAR_deployment_template_id":          "aws-general-purpose",
		"TF_VAR_integration_server_docker_image": "docker.elastic.co/beats-ci/elastic-agent-cloud-fips:git-${BUILDKITE_COMMIT:0:12}",
		"TF_VAR_docker_images_name_suffix":       "-fips",
	}
}

// BKIntegrationFIPSPipeline generates the .buildkite/bk.integration-fips.pipeline.yml pipeline.
// This pipeline runs FIPS-specific integration tests.
func BKIntegrationFIPSPipeline() *pipeline.Pipeline {
	p := pipeline.New().
		Env("ASDF_MAGE_VERSION", "1.14.0").
		Env("MS_GOTOOLCHAIN_TELEMETRY_ENABLED", "0").
		// Image environment variables - managed by updatecli
		Env("IMAGE_UBUNTU_2404_X86_64", pipeline.ImageUbuntu2404X86).
		Env("IMAGE_UBUNTU_X86_64_FIPS", pipeline.ImageUbuntuX86FIPS).
		Env("IMAGE_UBUNTU_ARM64_FIPS", pipeline.ImageUbuntuARM64FIPS).
		Env("ASDF_TERRAFORM_VERSION", "1.9.2")

	// Start ESS stack for FIPS integration tests
	p.Add(fipsEssStartStep())

	// FIPS Ubuntu tests group
	p.Add(fipsUbuntuTestsGroup())

	// ESS FIPS stack cleanup
	p.Add(fipsEssCleanupStep())

	// Aggregate test reports
	p.Add(fipsAggregateReportsStep())

	return p
}

// fipsEssStartStep creates the Start ESS stack step for FIPS tests.
func fipsEssStartStep() *pipeline.CommandStep {
	step := pipeline.CommandWithKey("Start ESS stack for FIPS integration tests", "integration-fips-ess",
		"source .buildkite/scripts/steps/ess_start.sh")

	pipeline.SetDependsOn(step, "packaging-containers-amd64-fips", "packaging-containers-arm64-fips")

	env := fipsCommonEnv()
	pipeline.SetEnv(step, env)

	pipeline.SetArtifactPaths(step, "test_infra/ess/*.tfstate", "test_infra/ess/*.lock.hcl")
	pipeline.SetAgent(step, pipeline.DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5"))
	pipeline.WithVaultECKeyStagingGov(step)

	return step
}

// fipsUbuntuTestsGroup creates the FIPS Ubuntu tests group.
func fipsUbuntuTestsGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey("fips:Stateful:Ubuntu", "integration-tests-ubuntu-fips")
	pipeline.SetGroupDependsOn(group, "integration-fips-ess")

	// fips:x86_64:sudo-{{matrix.sudo}}:{{matrix.groups}}
	x86Test := fipsUbuntuTestStep("fips:x86_64:sudo-{{matrix.sudo}}:{{matrix.groups}}",
		"packaging-amd64-fips",
		"buildkite-agent artifact download build/distributions/** . --step 'packaging-amd64-fips'\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix.groups}} {{matrix.sudo}}",
		"${IMAGE_UBUNTU_X86_64_FIPS}",
		"m5.2xlarge")
	pipeline.AddGroupStep(group, x86Test)

	// fips:arm64:sudo-{{matrix.sudo}}:{{matrix.groups}}
	arm64Test := fipsUbuntuTestStep("fips:arm64:sudo-{{matrix.sudo}}:{{matrix.groups}}",
		"packaging-arm64-fips",
		"buildkite-agent artifact download build/distributions/** . --step 'packaging-arm64-fips'\n.buildkite/scripts/steps/integration_tests_tf.sh {{matrix.groups}} {{matrix.sudo}}",
		"${IMAGE_UBUNTU_ARM64_FIPS}",
		"m6g.2xlarge")
	pipeline.AddGroupStep(group, arm64Test)

	// fips:upgrade-ech-deployment
	upgradeEch := fipsUpgradeEchStep()
	pipeline.AddGroupStep(group, upgradeEch)

	return group
}

// fipsUbuntuTestStep creates a FIPS Ubuntu test step with matrix.
func fipsUbuntuTestStep(label, dependsOn, command, image, instanceType string) *pipeline.CommandStep {
	step := pipeline.Command(label, command)
	pipeline.SetDependsOn(step, dependsOn)

	env := fipsCommonEnv()
	env["TEST_PACKAGE"] = "github.com/elastic/elastic-agent/testing/integration/ess"
	pipeline.SetEnv(step, env)

	pipeline.SetArtifactPaths(step, "build/**", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.AWSAgent(image, instanceType))
	pipeline.WithVaultECKeyStagingGov(step)
	pipeline.SetMatrix(step, map[string][]string{
		"sudo":   {"false", "true"},
		"groups": {"fleet"},
	})

	return step
}

// fipsUpgradeEchStep creates the FIPS upgrade ECH deployment step.
func fipsUpgradeEchStep() *pipeline.CommandStep {
	step := pipeline.Command("fips:upgrade-ech-deployment",
		".buildkite/scripts/buildkite-integration-tests.sh ech-deployment false")

	pipeline.SetIf(step, `build.env("BUILDKITE_PULL_REQUEST") != "false" &&  build.env("GITHUB_PR_LABELS") =~ /.*(Testing:run:TestUpgradeIntegrationsServer).*/`)

	pipeline.SetEnv(step, map[string]string{
		"FIPS":         "true",
		"EC_ENDPOINT":  "https://api.staging.elastic-gov.com",
		"ESS_REGION":   "us-gov-east-1",
		"TEST_PACKAGE": "github.com/elastic/elastic-agent/testing/integration/ess",
	})

	pipeline.SetArtifactPaths(step, "build/**", "build/diagnostics/**")
	pipeline.SetRetryAutomatic(step, 1)
	pipeline.SetAgent(step, pipeline.AWSAgent("${IMAGE_UBUNTU_X86_64_FIPS}", "m5.2xlarge"))
	pipeline.WithVaultECKeyStagingGov(step)

	return step
}

// fipsEssCleanupStep creates the ESS FIPS stack cleanup step.
func fipsEssCleanupStep() *pipeline.CommandStep {
	step := pipeline.Command("ESS FIPS stack cleanup",
		`buildkite-agent artifact download "test_infra/ess/**" . --step "integration-fips-ess"
ls -lah test_infra/ess
.buildkite/scripts/steps/ess_down.sh`)

	pipeline.SetDependsOn(step, "integration-tests-ubuntu-fips")

	env := fipsCommonEnv()
	pipeline.SetEnv(step, env)

	pipeline.SetAllowDependencyFailure(step, true)
	pipeline.SetAgent(step, pipeline.DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5"))
	pipeline.WithVaultECKeyStagingGov(step)

	return step
}

// fipsAggregateReportsStep creates the FIPS Aggregate test reports step.
func fipsAggregateReportsStep() *pipeline.CommandStep {
	step := pipeline.Command("Aggregate test reports",
		`buildkite-agent artifact download "build/*.xml" .`)

	pipeline.SetDependsOn(step, "integration-tests-ubuntu-fips")
	pipeline.SetAllowDependencyFailure(step, true)
	pipeline.SetAgent(step, pipeline.DockerAgentWithHooks("docker.elastic.co/ci-agent-images/platform-ingest/buildkite-agent-beats-ci-with-hooks:0.5"))
	pipeline.SetSoftFailExitStatus(step, "*")
	pipeline.WithVaultBuildkiteAnalytics(step)
	pipeline.WithTestCollector(step, "build/*.xml", "junit")

	return step
}

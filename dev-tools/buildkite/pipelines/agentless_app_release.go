// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// AgentlessAppRelease generates the pipeline.agentless-app-release.yaml pipeline.
// This pipeline builds and publishes the agentless service container to the internal registry.
func AgentlessAppRelease() *pipeline.Pipeline {
	// Packaging step for linux/amd64
	packagingAmd64 := pipeline.CommandWithKey(
		"Packaging: Service Container linux/amd64",
		"packaging-service-container-amd64",
		".buildkite/scripts/steps/integration-package.sh",
	)
	pipeline.SetEnv(packagingAmd64, map[string]string{
		"PACKAGES":        "docker",
		"PLATFORMS":       "linux/amd64",
		"DOCKER_VARIANTS": "service",
	})
	pipeline.SetArtifactPaths(packagingAmd64, "build/distributions/elastic-agent-service-git-*.docker.tar.gz")
	pipeline.SetAgent(packagingAmd64, pipeline.Agent{
		"provider":    "gcp",
		"machineType": "c2-standard-16",
		"diskSizeGb":  400,
	})

	// Packaging step for linux/arm64
	packagingArm64 := pipeline.CommandWithKey(
		"Packaging: Service Container linux/arm64",
		"packaging-service-container-arm64",
		".buildkite/scripts/steps/integration-package.sh",
	)
	pipeline.SetEnv(packagingArm64, map[string]string{
		"PACKAGES":        "docker",
		"PLATFORMS":       "linux/arm64",
		"DOCKER_VARIANTS": "service",
	})
	pipeline.SetArtifactPaths(packagingArm64, "build/distributions/elastic-agent-service-git-*.docker.tar.gz")
	pipeline.SetAgent(packagingArm64, pipeline.Agent{
		"provider":     "aws",
		"instanceType": "t4g.2xlarge",
		"imagePrefix":  "core-ubuntu-2204-aarch64",
		"diskSizeGb":   400,
	})

	// Publish to internal registry
	publishStep := pipeline.CommandWithKey(
		"Publish to internal registry",
		"mirror-elastic-agent",
		".buildkite/scripts/steps/ecp-internal-release.sh",
	)
	pipeline.SetAgent(publishStep, pipeline.Agent{
		"provider":    "gcp",
		"machineType": "c2-standard-16",
	})
	pipeline.AddPlugin(publishStep, "elastic/vault-docker-login#v0.5.2", map[string]any{
		"secret_path": "kv/ci-shared/platform-ingest/elastic_docker_registry",
	})

	// Validate docker image
	validateStep := pipeline.Command(
		":docker: Validate docker image is built for all architectures",
		".buildkite/scripts/steps/validate-agentless-docker-image.sh",
	)
	pipeline.AddEnv(validateStep, "SERVICE_VERSION", "${VERSION}")
	pipeline.SetAgent(validateStep, pipeline.Agent{
		"image": "docker.elastic.co/ci-agent-images/observability/oci-image-tools-agent:latest@sha256:a4ababd1347111759babc05c9ad5a680f4af48892784951358488b7e7fc94af9",
	})
	pipeline.AddPlugin(validateStep, "elastic/vault-docker-login#v0.6.3", map[string]any{
		"secret_path": "kv/ci-shared/platform-ingest/elastic_docker_registry",
	})

	// Promote agentless app release
	// Note: $$ is Buildkite's escape sequence for $ to prevent variable interpolation
	promoteCommand := `export COMMIT_HASH=$$(buildkite-agent meta-data get git-short-commit)
if [ $$(buildkite-agent step get "outcome" --step "mirror-elastic-agent") == "passed" ]; then
    cat <<- YAML | buildkite-agent pipeline upload
    steps:
    - label: ":serverless::argo: Run synthetics tests and update agentless to $${COMMIT_HASH} in serverless-gitops"
      async: true
      branches: main
      trigger: gpctl-promote-after-serverless-devenv-synthetics
      build:
        env:
          SERVICE_COMMIT_HASH: $${COMMIT_HASH}
          SERVICE: agentless
          SYNTHETICS_PROJECT: "agentless"
          SYNTHETICS_TAG: "agentless-ci"
YAML
fi`
	promoteStep := pipeline.Command(
		":grey_question: Promote agentless app release if validation passes",
		promoteCommand,
	)
	pipeline.SetIf(promoteStep, `build.env("DRY_RUN") == null || build.env("DRY_RUN") == "false"`)
	pipeline.SetDependsOn(promoteStep, "mirror-elastic-agent")
	pipeline.SetAgent(promoteStep, pipeline.Agent{
		"image": "docker.elastic.co/ci-agent-images/serverless-helm-builder:0.0.2@sha256:d00e8a7a0ab3618cfaacb0a7b1e1b06ee29728eb2b44de602374bd8f6b9b92ac",
	})

	return pipeline.New().
		Env("VERSION", "${BUILDKITE_COMMIT:0:12}").
		Add(packagingAmd64).
		Add(packagingArm64).
		Wait().
		Add(publishStep).
		Wait().
		Add(validateStep).
		Wait().
		Add(promoteStep)
}

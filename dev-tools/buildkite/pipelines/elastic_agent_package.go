// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// ElasticAgentPackage generates the .buildkite/pipeline.elastic-agent-package.yml pipeline.
// This pipeline handles DRA (Daily Release Automation) packaging.
func ElasticAgentPackage() *pipeline.Pipeline {
	p := pipeline.New().
		Env("BEAT_NAME", "elastic-agent").
		Env("BEAT_URL", "https://www.elastic.co/elastic-agent").
		Env("IMAGE_UBUNTU_2404_X86_64", pipeline.ImageUbuntu2404X86).
		Env("IMAGE_UBUNTU_2404_ARM_64", pipeline.ImageUbuntu2404ARM)

	// Input step for build parameters
	input := pipeline.Input("Build parameters")
	pipeline.SetInputIf(input, `build.env("MANIFEST_URL") == null`)
	pipeline.AddInputField(input, "MANIFEST_URL", "MANIFEST_URL", "", "Link to the build manifest URL.", true)
	pipeline.AddSelectField(input, "Mage verbose", "MAGEFILE_VERBOSE", "Increase verbosity of the mage commands, defaults to 0", false,
		pipeline.SelectOption{Label: "True", Value: "1"},
		pipeline.SelectOption{Label: "False", Value: "0"},
	)
	pipeline.AddSelectField(input, "DRA Workflow", "DRA_WORKFLOW", "What workflow of the DRA release process this build is going to be triggered for", true,
		pipeline.SelectOption{Label: "snapshot", Value: "snapshot"},
		pipeline.SelectOption{Label: "staging", Value: "staging"},
	)
	pipeline.AddInputField(input, "DRA Version", "DRA_VERSION", "", "The packaging version to use", true)
	pipeline.AddSelectField(input, "DRA DRY-RUN", "DRA_DRY_RUN", "If the DRA release manager script would actually publish anything or just print", false,
		pipeline.SelectOption{Label: "True", Value: "--dry-run"},
		pipeline.SelectOption{Label: "False", Value: ""},
	)
	p.Add(input)

	// Conditional wait after input
	p.Add(pipeline.WaitIf(`build.env("MANIFEST_URL") == null`))

	// Packaging group
	p.Add(packageGroup())

	// DRA publish step
	p.Add(draPublishStep())

	// BK API publish for independent agent release
	p.Add(bkAPIPublishStep())

	return p
}

// packageGroup creates the packaging artefacts group.
func packageGroup() *pipeline.GroupStep {
	group := pipeline.GroupWithKey(":Packaging Artefacts", "package")

	// Cross-platform packaging (x86_64)
	crossBuild := draPackageStep(
		":package: FIPS={{matrix.fips}} Cross Building and package elastic-agent",
		"package_elastic-agent",
		"gcp",
		"c2-standard-16",
		"${IMAGE_UBUNTU_2404_X86_64}",
		400,
		"linux/amd64 windows/amd64 darwin/amd64",
		"",
		true, // with docker login
	)
	pipeline.AddGroupStep(group, crossBuild)

	// ARM packaging
	armBuild := draPackageStep(
		":package: FIPS={{matrix.fips}} Package ARM elastic-agent",
		"package_elastic-agent-arm",
		"aws",
		"t4g.2xlarge",
		"${IMAGE_UBUNTU_2404_ARM_64}",
		400,
		"linux/arm64 darwin/arm64 windows/arm64",
		"docker,tar.gz,deb,rpm,zip",
		false, // no docker login
	)
	pipeline.AddGroupStep(group, armBuild)

	return group
}

// draPackageStep creates a DRA packaging step with matrix for FIPS.
func draPackageStep(label, key, provider, machineType, image string, diskSize int, platforms, packages string, dockerLogin bool) *pipeline.CommandStep {
	command := `if [[ -z "$${MANIFEST_URL}" ]]; then
  export MANIFEST_URL=$(buildkite-agent meta-data get MANIFEST_URL --default "")
  if [[ -z "$${MANIFEST_URL}" ]]; then
    echo ":broken_heart: Missing MANIFEST_URL variable or empty string provided"
    exit 1
  fi
fi
if [[ -z "$${MAGEFILE_VERBOSE}" ]]; then
  export MAGEFILE_VERBOSE=$(buildkite-agent meta-data get MAGEFILE_VERBOSE --default "0")
fi
.buildkite/scripts/steps/package.sh`

	// ARM build has additional multiarch setup
	if provider == "aws" {
		command = `echo "Add support for multiarch"
docker run --privileged --rm tonistiigi/binfmt:master --install all

` + command + `
ls -lahR build/`
	}

	step := pipeline.CommandWithKey(label, key, command)

	env := map[string]string{
		"PLATFORMS": platforms,
		"FIPS":      "{{matrix.fips}}",
	}
	if packages != "" {
		env["PACKAGES"] = packages
	}
	pipeline.SetEnv(step, env)

	agent := pipeline.Agent{
		"provider":   provider,
		"image":      image,
		"diskSizeGb": diskSize,
	}
	if provider == "gcp" {
		agent["machineType"] = machineType
	} else {
		agent["instanceType"] = machineType
	}
	pipeline.SetAgent(step, agent)

	pipeline.SetArtifactPaths(step, "build/distributions/**/*")

	// Matrix for FIPS true/false
	pipeline.SetMatrix(step, map[string][]string{
		"fips": {"false", "true"},
	})

	if dockerLogin {
		pipeline.WithVaultDockerLogin(step)
	}

	return step
}

// draPublishStep creates the DRA publish step.
func draPublishStep() *pipeline.CommandStep {
	command := `echo "+++ Restoring Artifacts"
buildkite-agent artifact download "build/**/*" .

echo "+++ Changing permissions for the release manager"
sudo chmod -R a+r build/distributions/
sudo chown -R :1000 build/distributions/
ls -lahR build/

echo "+++ Running DRA publish step"
if [[ -z "$${MAGEFILE_VERBOSE}" ]]; then
  export MAGEFILE_VERBOSE=$(buildkite-agent meta-data get MAGEFILE_VERBOSE --default "0")
fi
if [[ -z "$${DRA_DRY_RUN}" ]]; then
  DRA_DRY_RUN=$(buildkite-agent meta-data get DRA_DRY_RUN --default "")
  export DRA_DRY_RUN
fi
if [[ -z "$${DRA_VERSION}" ]]; then
  DRA_VERSION=$(buildkite-agent meta-data get DRA_VERSION --default "")
  export DRA_VERSION
fi
if [[ -z "$${DRA_WORKFLOW}" ]]; then
  DRA_WORKFLOW=$(buildkite-agent meta-data get DRA_WORKFLOW --default "")
  export DRA_WORKFLOW
fi
.buildkite/scripts/steps/dra-publish.sh`

	step := pipeline.CommandWithKey(":elastic-stack: Publishing to DRA", "dra-publish", command)
	pipeline.SetIf(step, `build.env("BUILDKITE_TRIGGERED_FROM_BUILD_PIPELINE_SLUG") == null || build.env("BUILDKITE_TRIGGERED_FROM_BUILD_PIPELINE_SLUG") != "independent-agent-release-staging"`)
	pipeline.SetDependsOn(step, "package")
	pipeline.SetAgent(step, pipeline.Agent{
		"provider": "gcp",
		"image":    "${IMAGE_UBUNTU_2404_X86_64}",
	})
	pipeline.SetEnv(step, map[string]string{
		"DRA_PROJECT_ID":          "elastic-agent-package",
		"DRA_PROJECT_ARTIFACT_ID": "agent-package",
	})

	return step
}

// bkAPIPublishStep creates the BK API publish step for independent agent release.
func bkAPIPublishStep() *pipeline.CommandStep {
	command := `echo "+++ Restoring Artifacts"
buildkite-agent artifact download "build/**/*" .
echo "+++ Changing permissions for the BK API commands"
sudo chown -R :1000 build/distributions/
echo "--- File listing"
ls -alR build
echo "--- Copy workaround for ironbank container filename"
.buildkite/scripts/steps/ironbank-cp-workaround.sh
echo "--- File listing after workaround"
ls -alR build
echo "+++ Checking artifact validity with release-manager collect dry run"
DRA_DRY_RUN="--dry-run"
export DRA_DRY_RUN
.buildkite/scripts/steps/dra-publish.sh
# Artifacts will be uploaded via the artifact_paths entry above
echo "+++ Set job metadata if TRIGGER_JOB_ID is properly set"
if [[ -z "$${TRIGGER_JOB_ID}" ]]; then
  echo "TRIGGER_JOB_ID is not set, so not setting metadata"
else
  # If a pipeline that triggered this build passes in a "TRIGGER_JOB_ID" env var, that
  # is an indicator that it will want us to set some metadata in that calling build
  # so that it can reference this specific build ID in order to easily download
  # artifacts saved off in this build.
  #
  # This is a much easier way to pull back artifacts from a triggered build than using
  # a Buildkite token that we then have to manage via vault, etc.
  # See: https://forum.buildkite.community/t/how-to-download-artifacts-back-from-triggered-pipeline/3480/2
  echo "Setting metadata for job that trigger this one"
  buildkite-agent meta-data set "triggered_build_id" "$BUILDKITE_BUILD_ID" --job $TRIGGER_JOB_ID
  buildkite-agent meta-data set "triggered_commit_hash" "$BUILDKITE_COMMIT" --job $TRIGGER_JOB_ID
fi`

	step := pipeline.CommandWithKey("Publishing via BK API for Independent Agent Release", "bk-api-publish-independent-agent", command)
	pipeline.SetIf(step, `build.env("BUILDKITE_TRIGGERED_FROM_BUILD_PIPELINE_SLUG") == "independent-agent-release-staging"`)
	pipeline.SetDependsOn(step, "package")
	pipeline.SetAgent(step, pipeline.Agent{
		"provider":    "gcp",
		"machineType": pipeline.MachineTypeN2Standard8,
		"diskSizeGb":  400,
		"image":       "${IMAGE_UBUNTU_2404_X86_64}",
	})
	pipeline.SetEnv(step, map[string]string{
		"DRA_PROJECT_ID":          "elastic-agent-package",
		"DRA_PROJECT_ARTIFACT_ID": "agent-package",
	})
	pipeline.SetArtifactPaths(step, "build/distributions/**/*")

	return step
}

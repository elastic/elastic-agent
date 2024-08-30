// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package buildkite

type StepAgent struct {
	Provider     string `yaml:"provider,omitempty"`
	ImageProject string `yaml:"imageProject,omitempty"`
	MachineType  string `yaml:"machineType,omitempty"`
	Image        string `yaml:"image,omitempty"`
}

type Step struct {
	Key                    string            `yaml:"key,omitempty"`
	Label                  string            `yaml:"label,omitempty"`
	Group                  string            `yaml:"group,omitempty"`
	Command                string            `yaml:"command,omitempty"`
	Env                    map[string]string `yaml:"env,omitempty"`
	ArtifactPaths          []string          `yaml:"artifact_paths,omitempty"`
	Agents                 StepAgent         `yaml:"agents,omitempty"`
	DependsOn              []string          `yaml:"depends_on,omitempty"`
	AllowDependencyFailure bool              `yaml:"allow_dependency_failure,omitempty"`
	Steps                  []Step            `yaml:"steps,omitempty"`
}

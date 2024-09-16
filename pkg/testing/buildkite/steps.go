// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package buildkite

type StepAgent struct {
	Provider     string `json:"provider,omitempty" yaml:"provider,omitempty"`
	ImageProject string `json:"imageProject,omitempty" yaml:"imageProject,omitempty"`
	MachineType  string `json:"machineType,omitempty" yaml:"machineType,omitempty"`
	Image        string `json:"image,omitempty" yaml:"image,omitempty"`
}

type Step struct {
	Key                    string            `json:"key,omitempty" yaml:"key,omitempty"`
	Label                  string            `json:"label,omitempty" yaml:"label,omitempty"`
	Command                string            `json:"command,omitempty" yaml:"command,omitempty"`
	Env                    map[string]string `json:"env,omitempty" yaml:"env,omitempty"`
	ArtifactPaths          []string          `json:"artifact_paths,omitempty" yaml:"artifact_paths,omitempty"`
	Agents                 []StepAgent       `json:"agents,omitempty" yaml:"agents,omitempty"`
	DependsOn              []string          `json:"depends_on,omitempty" yaml:"depends_on,omitempty"`
	AllowDependencyFailure bool              `json:"allow_dependency_failure,omitempty" yaml:"allow_dependency_failure,omitempty"`
	Steps                  []Step            `json:"steps,omitempty" yaml:"steps,omitempty"`
}

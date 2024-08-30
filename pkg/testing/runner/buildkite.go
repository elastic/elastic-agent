// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"gopkg.in/yaml.v2"
	"strings"

	"github.com/elastic/elastic-agent/pkg/testing/buildkite"
)

var (
	StackAgent = buildkite.StepAgent{
		Provider:     "gcp",
		ImageProject: "elastic-images-qa",
		MachineType:  "n1-standard-8",                                    // does it need to be this large?
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2204", // is this the correct image for creating a stack?
	}
)

// Buildkite returns a computed set of steps to run the integration tests on buildkite.
func (r *Runner) Buildkite() (string, error) {
	stackSteps := map[string]buildkite.Step{}
	stackDepends := map[string][]string{}
	var steps []buildkite.Step

	// create the stack steps first
	for _, lb := range r.batches {
		if !lb.Skip && lb.Batch.Stack != nil {
			if lb.Batch.Stack.Version == "" {
				// no version defined on the stack; set it to the defined stack version
				lb.Batch.Stack.Version = r.cfg.StackVersion
			}
			_, ok := stackSteps[lb.Batch.Stack.Version]
			if !ok {
				// add a step for creating the stack
				stackStep := buildkite.Step{
					Label:   fmt.Sprintf("Integration Stack: %s", lb.Batch.Stack.Version),
					Key:     fmt.Sprintf("integration-stack-%s", lb.Batch.Stack.Version),
					Command: "TODO FOR CREATING THE STACK",
					Agents:  StackAgent,
				}
				steps = append(steps, stackStep)
				stackSteps[lb.Batch.Stack.Version] = stackStep
			}
		}
	}

	// generate the steps for the tests
	for _, lb := range r.batches {
		if lb.Skip {
			continue
		}
		agentStep, err := buildkite.GetAgent(lb.Batch)
		if err != nil {
			return "", fmt.Errorf("unable to get machine and image: %w", err)
		}
		if len(lb.Batch.Tests) > 0 {
			var group buildkite.Step
			group.Group = fmt.Sprintf("Integration Test (non-sudo): %s", lb.ID)
			group.Key = fmt.Sprintf("integration-non-sudo-%s", lb.ID)
			if lb.Batch.Stack != nil {
				stackKey := fmt.Sprintf("integration-stack-%s", lb.Batch.Stack.Version)
				group.DependsOn = append(group.DependsOn, stackKey)
				stackDepends[stackKey] = append(stackDepends[stackKey], group.Key)
			}
			group.ArtifactPaths = []string{"build/**"}
			group.Agents = agentStep
			group.Command = "mage integration:testOnRemote"
			group.Env = map[string]string{
				"AGENT_VERSION":      r.cfg.AgentVersion,
				"TEST_DEFINE_PREFIX": group.Key,
				"TEST_DEFINE_TESTS":  strings.Join(getTestNames(lb.Batch.Tests), ","),
			}
			steps = append(steps, group)
		}
		if len(lb.Batch.SudoTests) > 0 {
			var group buildkite.Step
			group.Group = fmt.Sprintf("Integration Test (sudo): %s", lb.ID)
			group.Key = fmt.Sprintf("integration-sudo-%s", lb.ID)
			if lb.Batch.Stack != nil {
				stackKey := fmt.Sprintf("integration-stack-%s", lb.Batch.Stack.Version)
				group.DependsOn = append(group.DependsOn, stackKey)
				stackDepends[stackKey] = append(stackDepends[stackKey], group.Key)
			}
			group.ArtifactPaths = []string{"build/**"}
			group.Agents = agentStep
			group.Command = "mage integration:testOnRemote"
			group.Env = map[string]string{
				"AGENT_VERSION":      r.cfg.AgentVersion,
				"TEST_DEFINE_PREFIX": group.Key,
				"TEST_DEFINE_TESTS":  strings.Join(getTestNames(lb.Batch.SudoTests), ","),
			}
			steps = append(steps, group)
		}
	}

	// add the teardown steps for the stacks
	for _, step := range stackSteps {
		steps = append(steps, buildkite.Step{
			Label:                  fmt.Sprintf("Teardown: %s", step.Label),
			Key:                    fmt.Sprintf("teardown-%s", step.Key),
			DependsOn:              stackDepends[step.Key],
			AllowDependencyFailure: true,
			Command:                "TODO FOR TEARING DOWN THE STACK",
			Agents:                 StackAgent,
		})
	}

	yamlOutput, err := yaml.Marshal(buildkite.Step{
		Group:     "Integration Tests",
		Key:       "integration-tests",
		DependsOn: []string{"package-it"},
		Steps:     steps,
	})
	if err != nil {
		return "", fmt.Errorf("unable to marshal yaml: %w", err)
	}
	return string(yamlOutput), nil
}

func getTestNames(pt []define.BatchPackageTests) []string {
	var tests []string
	for _, pkg := range pt {
		for _, test := range pkg.Tests {
			tests = append(tests, fmt.Sprintf("%s:%s", pkg.Name, test.Name))
		}
	}
	return tests
}

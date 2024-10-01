// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package buildkite

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/supported"
)

const (
	defaultProvider         = "gcp"
	defaultImageProject     = "elastic-images-qa"
	defaultAMD64MachineType = "n1-standard-8"
	defaultARM64MachineType = "t2a-standard-8"
)

var (
	bkStackAgent = StepAgent{
		Provider:     "gcp",
		ImageProject: "elastic-images-qa",
		MachineType:  "n1-standard-8",                                    // does it need to be this large?
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2204", // is this the correct image for creating a stack?
	}
	bkUbuntuAMD64_2004 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2004",
	}
	bkUbuntuAMD64_2204 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2204",
	}
	bkUbuntuAMD64_2404 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2404",
	}
	bkUbuntuARM64_2004 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2004-arm",
	}
	bkUbuntuARM64_2204 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2204-arm",
	}
	bkUbuntuARM64_2404 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2404-arm",
	}
	bkRHELAMD64_8 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-rhel-8",
	}
	bkRHELARM64_8 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-rhel-8-arm",
	}
	bkWindowsAMD64_2019 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2019",
	}
	bkWindowsAMD64_2019_Core = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2019-core",
	}
	bkWindowsAMD64_2022 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2022",
	}
	bkWindowsAMD64_2022_Core = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2022-core",
	}
)

// getAgent returns the agent to use for the provided batch.
func getAgent(os common.SupportedOS) (StepAgent, error) {
	switch os.Arch {
	case define.AMD64:
		switch os.Type {
		case define.Linux:
			switch os.Distro {
			case "", "ubuntu": // default is Ubuntu
				switch os.Version {
				case "20.04":
					return bkUbuntuAMD64_2004, nil
				case "22.04":
					return bkUbuntuAMD64_2204, nil
				case "", "24.04": // default is 24.04
					return bkUbuntuAMD64_2404, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown ubuntu version: %s", os.Version)
				}
			case "rhel":
				switch os.Version {
				case "", "8": // default is 8
					return bkRHELAMD64_8, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown rhel version: %s", os.Version)
				}
			}
		case define.Kubernetes:
			return bkUbuntuAMD64_2404, nil
		case define.Windows:
			switch os.Version {
			case "2019":
				return bkWindowsAMD64_2019, nil
			case "2019-core":
				return bkWindowsAMD64_2019_Core, nil
			case "", "2022": // default is 2022
				return bkWindowsAMD64_2022, nil
			case "2022-core":
				return bkWindowsAMD64_2022_Core, nil
			default:
				return StepAgent{}, fmt.Errorf("unknown windows version: %s", os.Version)
			}
		}
	case define.ARM64:
		switch os.Type {
		case define.Linux:
			switch os.Distro {
			case "", "ubuntu": // default is Ubuntu
				switch os.Version {
				case "20.04":
					return bkUbuntuARM64_2004, nil
				case "22.04":
					return bkUbuntuARM64_2204, nil
				case "", "24.04": // default is 24.04
					return bkUbuntuARM64_2404, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown ubuntu version: %s", os.Version)
				}
			case "rhel":
				switch os.Version {
				case "", "8": // default is 8
					return bkRHELARM64_8, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown rhel version: %s", os.Version)
				}
			}
		case define.Kubernetes:
			return bkUbuntuARM64_2404, nil
		case define.Windows:
			return StepAgent{}, errors.New("windows ARM support not enabled")
		case define.Darwin:
			return StepAgent{}, errors.New("darwin ARM support not enabled")
		default:
			return StepAgent{}, fmt.Errorf("unknown OS type: %s", os.Type)
		}
	default:
		return StepAgent{}, fmt.Errorf("unknown architecture: %s", os.Arch)
	}
	return StepAgent{}, fmt.Errorf("case missing for %+v", os)
}

func getCommand(b common.OSBatch) string {
	if b.OS.Type == define.Linux {
		return "mage integration:testOnRemote"
	}
	return "TODO"
}

func shouldSkip(os common.SupportedOS) bool {
	if os.Arch == define.AMD64 && os.Type == define.Linux {
		// currently only linux/amd64 is being supported
		// (but all steps are generated)
		return false
	}
	return true
}

// GenerateSteps returns a computed set of steps to run the integration tests on buildkite.
func GenerateSteps(cfg common.Config, batches ...define.Batch) (string, error) {
	stackSteps := map[string]Step{}
	stackTeardown := map[string][]string{}
	var steps []Step

	// create the supported batches first
	platforms, err := cfg.GetPlatforms()
	if err != nil {
		return "", err
	}
	osBatches, err := supported.CreateBatches(batches, platforms, cfg.Groups, cfg.Matrix, cfg.SingleTest)
	if err != nil {
		return "", err
	}

	// create the stack steps first
	for _, lb := range osBatches {
		if !lb.Skip && lb.Batch.Stack != nil {
			if lb.Batch.Stack.Version == "" {
				// no version defined on the stack; set it to the defined stack version
				lb.Batch.Stack.Version = cfg.StackVersion
			}
			_, ok := stackSteps[lb.Batch.Stack.Version]
			if !ok {
				// add a step for creating the stack
				stackKey := getStackKey(lb.Batch.Stack)
				stackStep := Step{
					Label:   fmt.Sprintf("Integration Stack: %s", lb.Batch.Stack.Version),
					Key:     stackKey,
					Command: "false",
					Agents:  []StepAgent{bkStackAgent},
				}
				steps = append(steps, stackStep)
				stackSteps[lb.Batch.Stack.Version] = stackStep
				stackTeardown[stackKey] = append(stackTeardown[stackKey], stackKey)
			}
		}
	}

	// generate the steps for the tests
	for _, lb := range osBatches {
		if lb.Skip {
			continue
		}
		agentStep, err := getAgent(lb.OS)
		if err != nil {
			return "", fmt.Errorf("unable to get machine and image: %w", err)
		}
		if len(lb.Batch.Tests) > 0 {
			var step Step
			step.Label = fmt.Sprintf("Integration Test (non-sudo): %s", lb.ID)
			step.Key = fmt.Sprintf("integration-non-sudo-%s", lb.ID)
			if lb.Batch.Stack != nil {
				stackKey := getStackKey(lb.Batch.Stack)
				step.DependsOn = append(step.DependsOn, stackKey)
				stackTeardown[stackKey] = append(stackTeardown[stackKey], step.Key)
			}
			step.ArtifactPaths = []string{"build/**"}
			step.Agents = []StepAgent{agentStep}
			step.Env = map[string]string{
				"AGENT_VERSION":      cfg.AgentVersion,
				"TEST_DEFINE_PREFIX": step.Key,
				"TEST_DEFINE_TESTS":  strings.Join(getTestNames(lb.Batch.Tests), ","),
			}
			step.Command = getCommand(lb)
			step.Skip = shouldSkip(lb.OS)
			steps = append(steps, step)
		}
		if len(lb.Batch.SudoTests) > 0 {
			var step Step
			step.Label = fmt.Sprintf("Integration Test (sudo): %s", lb.ID)
			step.Key = fmt.Sprintf("integration-sudo-%s", lb.ID)
			if lb.Batch.Stack != nil {
				stackKey := getStackKey(lb.Batch.Stack)
				step.DependsOn = append(step.DependsOn, stackKey)
				stackTeardown[stackKey] = append(stackTeardown[stackKey], step.Key)
			}
			step.ArtifactPaths = []string{"build/**"}
			step.Agents = []StepAgent{agentStep}
			step.Env = map[string]string{
				"AGENT_VERSION":      cfg.AgentVersion,
				"TEST_DEFINE_PREFIX": step.Key,
				"TEST_DEFINE_TESTS":  strings.Join(getTestNames(lb.Batch.SudoTests), ","),
			}
			step.Command = getCommand(lb)
			step.Skip = shouldSkip(lb.OS)
			steps = append(steps, step)
		}
	}

	// add the teardown steps for the stacks
	for _, step := range stackSteps {
		steps = append(steps, Step{
			Label:                  fmt.Sprintf("Teardown: %s", step.Label),
			Key:                    fmt.Sprintf("teardown-%s", step.Key),
			DependsOn:              stackTeardown[step.Key],
			AllowDependencyFailure: true,
			Command:                "false",
			Agents:                 []StepAgent{bkStackAgent},
		})
	}

	yamlOutput, err := yaml.Marshal(Step{
		Steps: steps,
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

func getStackKey(s *define.Stack) string {
	version := strings.Replace(s.Version, ".", "-", -1)
	return fmt.Sprintf("integration-stack-%s", version)
}

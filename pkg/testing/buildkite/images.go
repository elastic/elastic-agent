// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package buildkite

import (
	"errors"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	defaultProvider         = "gcp"
	defaultImageProject     = "elastic-images-qa"
	defaultAMD64MachineType = "n1-standard-8"
	defaultARM64MachineType = "t2a-standard-8"
)

var (
	UbuntuAMD64_2004 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2004",
	}
	UbuntuAMD64_2204 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2204",
	}
	UbuntuAMD64_2404 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2404",
	}
	UbuntuARM64_2004 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2004-arm",
	}
	UbuntuARM64_2204 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2204-arm",
	}
	UbuntuARM64_2404 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-ubuntu-2404-arm",
	}
	RHELAMD64_8 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-rhel-8",
	}
	RHELARM64_8 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultARM64MachineType,
		Image:        "family/platform-ingest-elastic-agent-rhel-8-arm",
	}
	WindowsAMD64_2019 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2019",
	}
	WindowsAMD64_2019_Core = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2019-core",
	}
	WindowsAMD64_2022 = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2022",
	}
	WindowsAMD64_2022_Core = StepAgent{
		Provider:     defaultProvider,
		ImageProject: defaultImageProject,
		MachineType:  defaultAMD64MachineType,
		Image:        "family/platform-ingest-elastic-agent-windows-2022-core",
	}
)

// GetAgent returns the agent to use for the provided batch.
func GetAgent(batch define.Batch) (StepAgent, error) {
	switch batch.OS.Arch {
	case define.AMD64:
		switch batch.OS.Type {
		case define.Linux:
			switch batch.OS.Distro {
			case "", "ubuntu": // default is Ubuntu
				switch batch.OS.Version {
				case "20.04":
					return UbuntuAMD64_2004, nil
				case "22.04":
					return UbuntuAMD64_2204, nil
				case "", "24.04": // default is 24.04
					return UbuntuAMD64_2404, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown ubuntu version: %s", batch.OS.Version)
				}
			case "rhel":
				switch batch.OS.Version {
				case "", "8": // default is 8
					return RHELAMD64_8, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown rhel version: %s", batch.OS.Version)
				}
			}
		case define.Windows:
			switch batch.OS.Version {
			case "2019":
				return WindowsAMD64_2019, nil
			case "2019-core":
				return WindowsAMD64_2019_Core, nil
			case "", "2022": // default is 2022
				return WindowsAMD64_2022, nil
			case "2022-core":
				return WindowsAMD64_2022_Core, nil
			default:
				return StepAgent{}, fmt.Errorf("unknown windows version: %s", batch.OS.Version)
			}
		}
	case define.ARM64:
		switch batch.OS.Type {
		case define.Linux:
			switch batch.OS.Distro {
			case "", "ubuntu": // default is Ubuntu
				switch batch.OS.Version {
				case "20.04":
					return UbuntuARM64_2004, nil
				case "22.04":
					return UbuntuARM64_2204, nil
				case "", "24.04": // default is 24.04
					return UbuntuARM64_2404, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown ubuntu version: %s", batch.OS.Version)
				}
			case "rhel":
				switch batch.OS.Version {
				case "", "8": // default is 8
					return RHELARM64_8, nil
				default:
					return StepAgent{}, fmt.Errorf("unknown rhel version: %s", batch.OS.Version)
				}
			}
		case define.Windows:
			return StepAgent{}, errors.New("windows ARM support not enabled")
		case define.Darwin:
			return StepAgent{}, errors.New("darwin ARM support not enabled")
		default:
			return StepAgent{}, fmt.Errorf("unknown OS type: %s", batch.OS.Type)
		}
	default:
		return StepAgent{}, fmt.Errorf("unknown architecture: %s", batch.OS.Arch)
	}
	return StepAgent{}, fmt.Errorf("case missing for %+v", batch)
}

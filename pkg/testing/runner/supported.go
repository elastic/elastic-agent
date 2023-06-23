// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	// Google is for the Google Cloud Platform (GCP)
	Google = "google"

	// Ubuntu is a Linux distro.
	Ubuntu = "ubuntu"
)

var (
	// ErrOSNotSupported returned when it's an unsupported OS.
	ErrOSNotSupported = errors.New("os/arch not current supported")
)

// LayoutOS defines the minimal information for a mapping of an OS to the
// provider, instance size, and runs on for that OS.
type LayoutOS struct {
	OS           define.OS
	Provider     string
	InstanceSize string
	RunsOn       string
	Username     string
	RemotePath   string
	Runner       OSRunner
}

// Supported defines the set of supported OS's the runner currently supports.
//
// In the case that a batch is not specific on the version and/or distro the first
// one in this list will be picked. So it's best to place the one that we want the
// most testing at the top.
var supported = []LayoutOS{
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "22.04",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-2", // 2 amd64 cpus
		RunsOn:       "ubuntu-2204-lts",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
		Runner:       DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-2", // 2 amd64 cpus
		RunsOn:       "ubuntu-2004-lts",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
		Runner:       DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "22.04",
		},
		Provider:     Google,
		InstanceSize: "t2a-standard-2", // 2 arm64 cpus
		RunsOn:       "ubuntu-2204-lts-arm64",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
		Runner:       DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Provider:     Google,
		InstanceSize: "t2a-standard-2", // 2 arm64 cpus
		RunsOn:       "ubuntu-2004-lts-arm64",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
		Runner:       DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2022",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-4", // 4 amd64 cpus
		RunsOn:       "windows-2022",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
		Runner:       WindowsRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2022-core",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-4", // 4 amd64 cpus
		RunsOn:       "windows-2022-core",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
		Runner:       WindowsRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2019",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-4", // 4 amd64 cpus
		RunsOn:       "windows-2019",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
		Runner:       WindowsRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2019-core",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-4", // 4 amd64 cpus
		RunsOn:       "windows-2019-core",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
		Runner:       WindowsRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2016",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-4", // 4 amd64 cpus
		RunsOn:       "windows-2016",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
		Runner:       WindowsRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2016-core",
		},
		Provider:     Google,
		InstanceSize: "e2-standard-4", // 4 amd64 cpus
		RunsOn:       "windows-2016-core",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
		Runner:       WindowsRunner{},
	},
}

// getSupported returns all the supported layout based on the provided OS profile.
func getSupported(os define.OS) ([]LayoutOS, error) {
	var match []LayoutOS
	for _, s := range supported {
		if osMatch(s.OS, os) {
			match = append(match, s)
		}
	}
	if len(match) > 0 {
		return match, nil
	}
	return nil, fmt.Errorf("%w: %s/%s", ErrOSNotSupported, os.Type, os.Arch)
}

// osMatch returns true when the specific OS is a match for a non-specific OS.
func osMatch(specific define.OS, notSpecific define.OS) bool {
	if specific.Type != notSpecific.Type || specific.Arch != notSpecific.Arch {
		return false
	}
	if notSpecific.Distro != "" && specific.Distro != notSpecific.Distro {
		return false
	}
	if notSpecific.Version != "" && specific.Version != notSpecific.Version {
		return false
	}
	return true
}

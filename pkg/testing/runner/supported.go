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
	// Ubuntu is a Linux distro.
	Ubuntu = "ubuntu"
)

var (
	// ErrOSNotSupported returned when it's an unsupported OS.
	ErrOSNotSupported = errors.New("os/arch not currently supported")
)

// SupportedOS maps a OS definition to a OSRunner.
type SupportedOS struct {
	define.OS

	// Runner is the runner to use for the OS.
	Runner OSRunner
}

var (
	// ContainerUbuntuAMD64_2004 - Ubuntu (amd64) 22.04
	ContainerUbuntuAMD64_2004 = SupportedOS{
		OS: define.OS{
			Type:    define.Container,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Runner: DebianRunner{},
	}
	// ContainerUbuntuARM64_2004 - Ubuntu (amd64) 20.04
	ContainerUbuntuARM64_2004 = SupportedOS{
		OS: define.OS{
			Type:    define.Container,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Runner: DebianRunner{},
	}
	// UbuntuAMD64_2204 - Ubuntu (amd64) 22.04
	UbuntuAMD64_2204 = SupportedOS{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "22.04",
		},
		Runner: DebianRunner{},
	}
	// UbuntuAMD64_2004 - Ubuntu (amd64) 20.04
	UbuntuAMD64_2004 = SupportedOS{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Runner: DebianRunner{},
	}
	// UbuntuARM64_2204 - Ubuntu (arm64) 22.04
	UbuntuARM64_2204 = SupportedOS{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "22.04",
		},
		Runner: DebianRunner{},
	}
	// UbuntuARM64_2004 - Ubuntu (arm64) 20.04
	UbuntuARM64_2004 = SupportedOS{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Runner: DebianRunner{},
	}
	// WindowsAMD64_2022 - Windows (amd64) Server 2022
	WindowsAMD64_2022 = SupportedOS{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2022",
		},
		Runner: WindowsRunner{},
	}
	// WindowsAMD64_2022_Core - Windows (amd64) Server 2022 Core
	WindowsAMD64_2022_Core = SupportedOS{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2022-core",
		},
		Runner: WindowsRunner{},
	}
	// WindowsAMD64_2019 - Windows (amd64) Server 2019
	WindowsAMD64_2019 = SupportedOS{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2019",
		},
		Runner: WindowsRunner{},
	}
	// WindowsAMD64_2019_Core - Windows (amd64) Server 2019 Core
	WindowsAMD64_2019_Core = SupportedOS{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2019-core",
		},
		Runner: WindowsRunner{},
	}
	// WindowsAMD64_2016 - Windows (amd64) Server 2016
	WindowsAMD64_2016 = SupportedOS{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2016",
		},
		Runner: WindowsRunner{},
	}
	// WindowsAMD64_2016_Core - Windows (amd64) Server 2016 Core
	WindowsAMD64_2016_Core = SupportedOS{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2016-core",
		},
		Runner: WindowsRunner{},
	}
)

// supported defines the set of supported OS's.
//
// A provisioner might support a lesser number of this OS's, but the following
// are known to be supported by out OS runner logic.
//
// In the case that a batch is not specific on the version and/or distro the first
// one in this list will be picked. So it's best to place the one that we want the
// most testing at the top.
var supported = []SupportedOS{
	ContainerUbuntuAMD64_2004,
	ContainerUbuntuARM64_2004,
	UbuntuAMD64_2204,
	UbuntuAMD64_2004,
	UbuntuARM64_2204,
	UbuntuARM64_2004,
	WindowsAMD64_2022,
	WindowsAMD64_2022_Core,
	WindowsAMD64_2019,
	WindowsAMD64_2019_Core,
	WindowsAMD64_2016,
	WindowsAMD64_2016_Core,
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

// getSupported returns all the supported based on the provided OS profile while using
// the provided platforms as a filter.
func getSupported(os define.OS, platforms []define.OS) ([]SupportedOS, error) {
	var match []SupportedOS
	for _, s := range supported {
		if osMatch(s.OS, os) && allowedByPlatforms(s.OS, platforms) {
			match = append(match, s)
		}
	}
	if len(match) > 0 {
		return match, nil
	}
	return nil, fmt.Errorf("%w: %s/%s", ErrOSNotSupported, os.Type, os.Arch)
}

// allowedByPlatforms determines if the os is in the allowed list of platforms.
func allowedByPlatforms(os define.OS, platforms []define.OS) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, platform := range platforms {
		if ok := allowedByPlatform(os, platform); ok {
			return true
		}
	}
	return false
}

// allowedByPlatform determines if the platform allows this os.
func allowedByPlatform(os define.OS, platform define.OS) bool {
	if os.Type != platform.Type {
		return false
	}
	if platform.Arch == "" {
		// not specific on arch
		return true
	}
	if os.Arch != platform.Arch {
		return false
	}
	if platform.Type == define.Linux {
		// on linux distro is supported
		if platform.Distro == "" {
			// not specific on distro
			return true
		}
		if os.Distro != platform.Distro {
			return false
		}
	}
	if platform.Version == "" {
		// not specific on version
		return true
	}
	if os.Version != platform.Version {
		return false
	}
	return true
}

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

// SupportedOS maps a OS definition to a OSRunner.
type SupportedOS struct {
	define.OS

	// Runner is the runner to use for the OS.
	Runner OSRunner
}

// supported defines the set of supported OS's.
//
// A provisioner might support a lesser number of this OS's, but the following
// are known to be supported by out OS runner logic.
//
// In the case that a batch is not specific on the version and/or distro the first
// one in this list will be picked. So it's best to place the one that we want the
// most testing at the top.
var supported = []SupportedOS{
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "22.04",
		},
		Runner: DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Runner: DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "22.04",
		},
		Runner: DebianRunner{},
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  Ubuntu,
			Version: "20.04",
		},
		Runner: DebianRunner{},
	},
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

// getSupported returns all the supported based on the provided OS profile.
func getSupported(os define.OS) ([]SupportedOS, error) {
	var match []SupportedOS
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

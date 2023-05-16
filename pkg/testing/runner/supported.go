package runner

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"

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

// LayoutOSRunner provides an interface to run the tests on the OS.
type LayoutOSRunner interface {
	// Prepare prepares the runner to actual run on the host.
	Prepare(ctx context.Context, c *ssh.Client, instanceID string, arch string, goVersion string, repoArchive string, buildPath string) error
}

// LayoutOS defines the minimal information for a mapping of an OS to the
// provider, instance size, and runs on for that OS.
type LayoutOS struct {
	OS           define.OS
	Provider     string
	InstanceSize string
	RunsOn       string
	Username     string
	RemotePath   string
	Runner       LayoutOSRunner
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
}

// getSupported returns the supported layout based on the provided OS profile.
func getSupported(os define.OS) (LayoutOS, error) {
	for _, s := range supported {
		if osMatch(s.OS, os) {
			return s, nil
		}
	}
	return LayoutOS{}, fmt.Errorf("%w: %s/%s", ErrOSNotSupported, os.Type, os.Arch)
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

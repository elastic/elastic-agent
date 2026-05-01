// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gcloud

import (
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/supported"
)

// LayoutOS defines the mapping of an OS to the GCP machine type, image family,
// username, and remote path for that OS.
type LayoutOS struct {
	OS           define.OS
	InstanceSize string
	ImageFamily  string
	ImageProject string
	Username     string
	RemotePath   string
}

// gcloudSupported defines the set of supported OS's the gcloud provisioner supports.
//
// In the case that a batch is not specific on the version and/or distro the first
// one in this list will be picked. So it's best to place the one that we want the
// most testing at the top.
var gcloudSupported = []LayoutOS{
	// AMD64 Ubuntu
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  supported.Ubuntu,
			Version: "24.04",
		},
		InstanceSize: "e2-standard-2", // 2 amd64 cpus, 8 GB RAM
		ImageFamily:  "ubuntu-2404-lts-amd64",
		ImageProject: "ubuntu-os-cloud",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  supported.Ubuntu,
			Version: "22.04",
		},
		InstanceSize: "e2-standard-2",
		ImageFamily:  "ubuntu-2204-lts",
		ImageProject: "ubuntu-os-cloud",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  supported.Ubuntu,
			Version: "20.04",
		},
		InstanceSize: "e2-standard-2",
		ImageFamily:  "ubuntu-2004-lts",
		ImageProject: "ubuntu-os-cloud",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	// ARM64 Ubuntu
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  supported.Ubuntu,
			Version: "24.04",
		},
		InstanceSize: "t2a-standard-4", // 4 arm64 cpus, 16 GB RAM
		ImageFamily:  "ubuntu-2404-lts-arm64",
		ImageProject: "ubuntu-os-cloud",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  supported.Ubuntu,
			Version: "22.04",
		},
		InstanceSize: "t2a-standard-4",
		ImageFamily:  "ubuntu-2204-lts-arm64",
		ImageProject: "ubuntu-os-cloud",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  supported.Ubuntu,
			Version: "20.04",
		},
		InstanceSize: "t2a-standard-4",
		ImageFamily:  "ubuntu-2004-lts-arm64",
		ImageProject: "ubuntu-os-cloud",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	// RHEL
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  supported.Rhel,
			Version: "8",
		},
		InstanceSize: "e2-standard-2",
		ImageFamily:  "rhel-8",
		ImageProject: "rhel-cloud",
		Username:     "rhel",
		RemotePath:   "/home/rhel/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  supported.Rhel,
			Version: "10",
		},
		InstanceSize: "e2-standard-2",
		ImageFamily:  "rhel-10",
		ImageProject: "rhel-cloud",
		Username:     "rhel",
		RemotePath:   "/home/rhel/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  supported.Rhel,
			Version: "8",
		},
		InstanceSize: "t2a-standard-2",
		ImageFamily:  "rhel-8-arm64",
		ImageProject: "rhel-cloud",
		Username:     "rhel",
		RemotePath:   "/home/rhel/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  supported.Rhel,
			Version: "10",
		},
		InstanceSize: "t2a-standard-2",
		ImageFamily:  "rhel-10-arm64",
		ImageProject: "rhel-cloud",
		Username:     "rhel",
		RemotePath:   "/home/rhel/agent",
	},
	// Windows
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2022",
		},
		InstanceSize: "e2-highcpu-16", // 16 amd64 cpus, 16 GB RAM
		ImageFamily:  "windows-2022",
		ImageProject: "windows-cloud",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2022-core",
		},
		InstanceSize: "e2-highcpu-16",
		ImageFamily:  "windows-2022-core",
		ImageProject: "windows-cloud",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2019",
		},
		InstanceSize: "e2-highcpu-16",
		ImageFamily:  "windows-2019",
		ImageProject: "windows-cloud",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2019-core",
		},
		InstanceSize: "e2-highcpu-16",
		ImageFamily:  "windows-2019-core",
		ImageProject: "windows-cloud",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2016",
		},
		InstanceSize: "e2-highcpu-16",
		ImageFamily:  "windows-2016",
		ImageProject: "windows-cloud",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
	},
	{
		OS: define.OS{
			Type:    define.Windows,
			Arch:    define.AMD64,
			Version: "2016-core",
		},
		InstanceSize: "e2-highcpu-16",
		ImageFamily:  "windows-2016-core",
		ImageProject: "windows-cloud",
		Username:     "windows",
		RemotePath:   "C:\\Users\\windows\\agent",
	},
}

func findOSLayout(os define.OS) (LayoutOS, bool) {
	for _, s := range gcloudSupported {
		if s.OS == os {
			return s, true
		}
	}
	return LayoutOS{}, false
}

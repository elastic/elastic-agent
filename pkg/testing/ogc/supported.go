// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ogc

import (
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

// ogcSupported defines the set of supported OS's the OGC provisioner currently supports.
//
// In the case that a batch is not specific on the version and/or distro the first
// one in this list will be picked. So it's best to place the one that we want the
// most testing at the top.
var ogcSupported = []LayoutOS{
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  runner.Ubuntu,
			Version: "22.04",
		},
		Provider:     runner.Google,
		InstanceSize: "e2-standard-2", // 2 amd64 cpus
		RunsOn:       "ubuntu-2204-lts",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.AMD64,
			Distro:  runner.Ubuntu,
			Version: "20.04",
		},
		Provider:     runner.Google,
		InstanceSize: "e2-standard-2", // 2 amd64 cpus
		RunsOn:       "ubuntu-2004-lts",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  runner.Ubuntu,
			Version: "22.04",
		},
		Provider:     runner.Google,
		InstanceSize: "t2a-standard-2", // 2 arm64 cpus
		RunsOn:       "ubuntu-2204-lts-arm64",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
	{
		OS: define.OS{
			Type:    define.Linux,
			Arch:    define.ARM64,
			Distro:  runner.Ubuntu,
			Version: "20.04",
		},
		Provider:     runner.Google,
		InstanceSize: "t2a-standard-2", // 2 arm64 cpus
		RunsOn:       "ubuntu-2004-lts-arm64",
		Username:     "ubuntu",
		RemotePath:   "/home/ubuntu/agent",
	},
}

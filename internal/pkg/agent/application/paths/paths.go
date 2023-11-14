// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !darwin && !windows

package paths

const (
	// BinaryName is the name of the installed binary.
	BinaryName = "elastic-agent"

	// DefaultBasePath is the base path used by the install command
	// for installing Elastic Agent's files.
	DefaultBasePath = "/opt"

	// ControlSocketPath is the control socket path used when installed.
	ControlSocketPath = "unix:///run/elastic-agent.sock"

	// ControlSocketUnprivilegedPath is the control socket path used when installed as non-root.
	// This must exist inside of a directory in '/run/' because the permissions need to be set
	// on that directory during installation time, because once the service is spawned it will not
	// have permissions to create the socket in the '/run/' directory.
	ControlSocketUnprivilegedPath = "unix:///run/elastic-agent/elastic-agent.sock"

	// ShipperSocketPipePattern is the socket path used when installed for a shipper pipe.
	ShipperSocketPipePattern = "unix:///run/elastic-agent-%s-pipe.sock"

	// ServiceName is the service name when installed.
	ServiceName = "elastic-agent"

	// ShellWrapperPath is the path to the installed shell wrapper.
	ShellWrapperPath = "/usr/bin/elastic-agent"

	// ShellWrapper is the wrapper that is installed.  The %s must
	// be substituted with the appropriate top path.
	ShellWrapper = `#!/bin/sh
exec %s/elastic-agent $@
`
)

// ArePathsEqual determines whether paths are equal taking case sensitivity of os into account.
func ArePathsEqual(expected, actual string) bool {
	return expected == actual
}

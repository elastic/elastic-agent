// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package paths

const (
	// BinaryName is the name of the installed binary.
	BinaryName = "elastic-agent"

	// DevelopmentBinaryName is the name of the installed binary when --develop
	// flag is used
	DevelopmentBinaryName = "elastic-development-agent"

	// DefaultBasePath is the base path used by the install command
	// for installing Elastic Agent's files.
	DefaultBasePath = "/opt"

	// serviceName is the service name when installed.
	serviceName             = "elastic-agent"
	serviceNameNamespaceFmt = "elastic-agent-%s"

	// shellWrapperPath is the path to the installed shell wrapper.
	shellWrapperPath             = "/usr/bin/elastic-agent"
	shellWrapperPathNamespaceFmt = "/usr/bin/elastic-%s-agent"

	// ShellWrapper is the wrapper that is installed.  The %s must
	// be substituted with the appropriate top path.
	ShellWrapperFmt = `#!/bin/sh
exec %s/elastic-agent $@
`

	// controlSocketRunSymlink is the path to the symlink that should be
	// created to the control socket when Elastic Agent is running with root.
	controlSocketRunSymlink             = "/run/elastic-agent.sock"
	controlSocketRunSymlinkNamespaceFmt = "/run/elastic-agent-%s.sock"
)

// ArePathsEqual determines whether paths are equal taking case sensitivity of os into account.
func ArePathsEqual(expected, actual string) bool {
	return expected == actual
}

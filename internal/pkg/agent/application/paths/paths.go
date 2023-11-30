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

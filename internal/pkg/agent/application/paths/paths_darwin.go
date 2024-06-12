// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package paths

import (
	"fmt"
)

const (
	// BinaryName is the name of the installed binary.
	BinaryName = "elastic-agent"

	// DefaultBasePath is the base path used by the install command
	// for installing Elastic Agent's files.
	DefaultBasePath = "/Library"

	// controlSocketRunSymlink is the path to the symlink that should be
	// created to the control socket when Elastic Agent is running with root.
	controlSocketRunSymlink             = "/var/run/elastic-agent.sock"
	controlSocketRunSymlinkNamespaceFmt = "/var/run/elastic-agent-%s.sock"

	// serviceName is the service name when installed.
	serviceName             = "co.elastic.elastic-agent"
	serviceNameNamespaceFmt = "co.elastic.elastic-agent-%s"

	// shellWrapperPath is the path to the installed shell wrapper.
	shellWrapperPath             = "/usr/local/bin/elastic-agent"
	shellWrapperPathNamespaceFmt = "/usr/local/bin/elastic-%s-agent"

	// ShellWrapper is the wrapper that is installed.  The %s must
	// be substituted with the appropriate top path.
	ShellWrapperFmt = `#!/bin/sh
exec %s/elastic-agent $@
`
)

// shellWrapperPathForNamespace is a helper to work around not being able to use fmt.Sprintf
// unconditionally since shellWrapperPathNamespaceFmt is empty on Windows.
func shellWrapperPathForNamespace(namespace string) string {
	return fmt.Sprintf(shellWrapperPathNamespaceFmt, namespace)
}

// controlSocketRunSymlinkForNamespace is a helper to work around not being able to use fmt.Sprintf
// unconditionally since controlSocketRunSymlinkNamespaceFmt is empty on Windows.
func controlSocketRunSymlinkForNamespace(namespace string) string {
	return fmt.Sprintf(controlSocketRunSymlinkNamespaceFmt, namespace)
}

// ArePathsEqual determines whether paths are equal taking case sensitivity of os into account.
func ArePathsEqual(expected, actual string) bool {
	return expected == actual
}

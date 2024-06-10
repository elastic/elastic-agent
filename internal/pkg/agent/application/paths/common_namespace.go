// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// This file encapsulates the common paths that need to account for installation namepsaces.
// Installation namespaces allow multiple agents on the same machine.
package paths

import (
	"path/filepath"
	"strings"
)

// installNamespace is the name of the agent's current installation namepsace.
var installNamespace string

const (
	// installDirNamespaceFmt is the format of the directory agent will be installed to within the base path when using an installation namepsace.
	// For example it is $BasePath/$DevelopmentInstallDirName, on MacOS it is /Library/Elastic/$DevelopmentInstallDirName.
	installDir             = "Agent"
	installDirNamespaceFmt = "Agent-%s"

	// DevelopmentNamespace defines the "well known" development namespace.
	DevelopmentNamespace = "Development"

	// Service display names. Must be different from the ServiceName() on Windows.
	serviceDisplayName             = "Elastic Agent"
	serviceDisplayNameNamespaceFmt = "Elastic Agent - %s"
)

// SetInstallNamespace sets whether the agent is currently in or is being installed in an installation namespace.
func SetInstallNamespace(namespace string) {
	installNamespace = namespace
}

// InstallNamespace returns the name of the current installation namespace. Returns the empty string
// for the default namespace. For installed agents, the namespace is parsed from the installation
// directory name, since a unique directory name is required to avoid collisions between installed
// agents in the same base path. Before installation, the installation namespace must be configured
// using SetInstallNamespace().
func InstallNamespace() string {
	if installNamespace != "" {
		return installNamespace
	}

	if RunningInstalled() {
		return parseNamespaceFromDir(filepath.Base(Top()))
	}

	return ""
}

func parseNamespaceFromDir(dir string) string {
	parts := strings.SplitAfterN(dir, "-", 2)
	if len(parts) <= 1 {
		return ""
	}

	return parts[1]
}

// InInstallNamespace returns true if the agent is being installed in an installation namespace.
func InInstallNamespace() bool {
	return InstallNamespace() != ""
}

// InstallDirNameForNamespace returns the installation directory name for a given namespace.
// The installation directory name with a namespace is $BasePath/InstallDirNameForNamespace().
func InstallDirNameForNamespace(namespace string) string {
	if namespace == "" {
		return installDir
	}

	// Use strings.Replace() to avoid having to sanitize format specifiers in the namespace itself.
	return strings.Replace(installDirNamespaceFmt, "%s", namespace, 1)
}

// InstallPath returns the top level directory Agent will be installed into, accounting for any namespace.
func InstallPath(basePath string) string {
	namespace := InstallNamespace()
	if namespace == "" {
		return filepath.Join(basePath, "Elastic", installDir)
	}

	return filepath.Join(basePath, "Elastic", InstallDirNameForNamespace(namespace))
}

// ServiceName returns the service name accounting for any namespace.
func ServiceName() string {
	namespace := InstallNamespace()
	if namespace == "" {
		return serviceName
	}

	// Use strings.Replace() to avoid having to sanitize format specifiers in the namespace itself.
	return strings.Replace(serviceNameNamespaceFmt, "%s", namespace, 1)
}

// ServiceDisplayName returns the service display name accounting for any namespace.
func ServiceDisplayName() string {
	namespace := InstallNamespace()
	if namespace == "" {
		return serviceDisplayName
	}

	// Use strings.Replace() to avoid having to sanitize format specifiers in the namespace itself.
	return strings.Replace(serviceDisplayNameNamespaceFmt, "%s", namespace, 1)
}

// ShellWrapperPath returns the shell wrapper path accounting for any namespace.
// The provided namespace is always lowercased for consistency.
func ShellWrapperPath() string {
	namespace := InstallNamespace()
	if namespace == "" {
		return shellWrapperPath
	}

	// Use strings.Replace() to avoid having to sanitize format specifiers in the namespace itself.
	return strings.Replace(shellWrapperPathNamespaceFmt, "%s", strings.ToLower(namespace), 1)
}

// ControlSocketRunSymlink returns the shell wrapper path accounting for any namespace.
// Does not auto detect the namespace because it is used outside of agent itself in the testing framework.
func ControlSocketRunSymlink(namespace string) string {
	if namespace == "" {
		return controlSocketRunSymlink
	}

	// Use strings.Replace() to avoid having to sanitize format specifiers in the namespace itself.
	return strings.Replace(controlSocketRunSymlinkNamespaceFmt, "%s", namespace, 1)
}

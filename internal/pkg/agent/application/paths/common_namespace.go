// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package paths

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// installDirNamespaceFmt is the format of the directory agent will be installed to within the base path when using an installation namepsace.
	// It is $BasePath/Agent-$namespace.
	installDir                = "Agent"
	installDirNamespaceSep    = "-"
	installDirNamespacePrefix = installDir + installDirNamespaceSep
	installDirNamespaceFmt    = installDirNamespacePrefix + "%s"

	// DevelopmentNamespace defines the "well known" development namespace.
	DevelopmentNamespace = "Development"

	// Service display names. Must be different from the ServiceName() on Windows.
	serviceDisplayName             = "Elastic Agent"
	serviceDisplayNameNamespaceFmt = "Elastic Agent - %s"
)

// installNamespace is the name of the agent's current installation namepsace.
var installNamespace string

// SetInstallNamespace sets whether the agent is currently in or is being installed in an installation namespace.
// Removes leading and trailing whitespace
func SetInstallNamespace(namespace string) {
	installNamespace = strings.TrimSpace(namespace)
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
		// Parse the namespace from the directory once to ensure deterministic behavior from startup.
		namespace := parseNamespaceFromDir(filepath.Base(Top()))
		installNamespace = namespace
	}

	return ""
}

func parseNamespaceFromDir(dir string) string {
	parts := strings.SplitAfterN(dir, "-", 2)
	if len(parts) <= 1 {
		return ""
	} else if parts[0] != installDirNamespacePrefix {
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

	return fmt.Sprintf(installDirNamespaceFmt, namespace)
}

// InstallPath returns the top level directory Agent will be installed into, accounting for any namespace.
func InstallPath(basePath string) string {
	namespace := InstallNamespace()
	return filepath.Join(basePath, "Elastic", InstallDirNameForNamespace(namespace))
}

// ServiceName returns the service name accounting for any namespace.
func ServiceName() string {
	namespace := InstallNamespace()
	if namespace == "" {
		return serviceName
	}

	return fmt.Sprintf(serviceNameNamespaceFmt, namespace)
}

// ServiceDisplayName returns the service display name accounting for any namespace.
func ServiceDisplayName() string {
	namespace := InstallNamespace()
	if namespace == "" {
		return serviceDisplayName
	}

	return fmt.Sprintf(serviceDisplayNameNamespaceFmt, namespace)
}

// ShellWrapperPath returns the shell wrapper path accounting for any namespace.
// The provided namespace is always lowercased for consistency.
func ShellWrapperPath() string {
	namespace := InstallNamespace()
	if namespace == "" {
		return shellWrapperPath
	}

	return ShellWrapperPathForNamespace(namespace)
}

// ControlSocketRunSymlink returns the shell wrapper path accounting for any namespace.
// Does not auto detect the namespace because it is used outside of agent itself in the testing framework.
func ControlSocketRunSymlink(namespace string) string {
	if namespace == "" {
		return controlSocketRunSymlink
	}

	return controlSocketRunSymlinkForNamespace(namespace)
}

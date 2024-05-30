// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package paths

import "path/filepath"

// DevelopmentInstallDirName is the name of the directory agent will be installed to within the base path.
// For example it is $BasePath/$DevelopmentInstallDirName, on MacOS it is /Library/Elastic/$DevelopmentInstallDirName.
const DevelopmentInstallDirName string = "DevelopmentAgent"

var isDevelopmentMode bool

// SetIsDevelopmentMode sets whether the agent is installed in development mode or not.
func SetIsDevelopmentMode(developmentMode bool) {
	isDevelopmentMode = developmentMode
}

// IsDevelopmentMode returns true if the agent is installed in development mode.
func IsDevelopmentMode() bool {
	// The current process has explicitly been told it is in development mode.
	if isDevelopmentMode {
		return true
	}

	// We are installed in development mode and have to infer it from the path.
	if RunningInstalled() && filepath.Base(Top()) == DevelopmentInstallDirName {
		return true
	}

	return false
}

// InstallPath returns the top level directory Agent will be installed into, accounting for development mode.
func InstallPath(basePath string) string {
	if IsDevelopmentMode() {
		return filepath.Join(basePath, "Elastic", DevelopmentInstallDirName)
	}
	return filepath.Join(basePath, "Elastic", "Agent")
}

// ServiceName returns the service name accounting for development mode.
func ServiceName() string {
	if IsDevelopmentMode() {
		return serviceNameDevelopmentMode
	}
	return serviceName
}

// ShellWrapperPath returns the shell wrapper path accounting for development mode.
func ShellWrapperPath() string {
	if IsDevelopmentMode() {
		return shellWrapperPathDevelopmentMode
	}
	return shellWrapperPath
}

// ControlSocketRunSymlink returns the shell wrapper path accounting for development mode.
func ControlSocketRunSymlink(isDevelopmentMode bool) string {
	if isDevelopmentMode {
		return controlSocketRunSymlinkDevelopmentMode
	}
	return controlSocketRunSymlink
}

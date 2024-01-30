// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package paths

import (
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// BinaryName is the name of the installed binary.
	BinaryName = "elastic-agent.exe"

	// DefaultBasePath is the base path used by the install command
	// for installing Elastic Agent's files.
	DefaultBasePath = `C:\Program Files`

	// ControlSocketRunSymlink is not created on Windows.
	ControlSocketRunSymlink = ""

	// ServiceName is the service name when installed.
	ServiceName = "Elastic Agent"

	// ShellWrapperPath is the path to the installed shell wrapper.
	ShellWrapperPath = "" // no wrapper on Windows

	// ShellWrapper is the wrapper that is installed.
	ShellWrapper = "" // no wrapper on Windows

	// defaultAgentVaultPath is the directory for windows where the vault store is located or the
	defaultAgentVaultPath = "vault"
)

// ArePathsEqual determines whether paths are equal taking case sensitivity of os into account.
func ArePathsEqual(expected, actual string) bool {
	return strings.EqualFold(expected, actual)
}

// AgentVaultPath is the directory that contains all the files for the value
func AgentVaultPath() string {
	return filepath.Join(Config(), defaultAgentVaultPath)
}

func initialControlSocketPath(topPath string) string {
	// when installed the control address is fixed
	if RunningInstalled() {
		return WindowsControlSocketInstalledPath
	}
	return ControlSocketFromPath(runtime.GOOS, topPath)
}

// ResolveControlSocket updates the control socket path.
//
// Called during the upgrade process from pre-8.8 versions. In pre-8.8 versions the
// RunningInstalled will always be false, even when it is an installed version. Once
// that is fixed from the upgrade process the control socket path needs to be updated.
func ResolveControlSocket() {
	currentPath := ControlSocket()
	if currentPath == ControlSocketFromPath(runtime.GOOS, topPath) && RunningInstalled() {
		// path is not correct being that it's installed
		// reset the control socket path to be the installed path
		SetControlSocket(WindowsControlSocketInstalledPath)
	}
}

// HasPrefix tests if the path starts with the prefix.
func HasPrefix(path string, prefix string) bool {
	if path == "" || prefix == "" {
		return false
	}

	if !strings.EqualFold(filepath.VolumeName(path), filepath.VolumeName(prefix)) {
		return false
	}

	prefixParts := pathSplit(filepath.Clean(prefix))
	pathParts := pathSplit(filepath.Clean(path))

	if len(prefixParts) > len(pathParts) {
		return false
	}

	for i := 0; i < len(prefixParts); i++ {
		if !strings.EqualFold(prefixParts[i], pathParts[i]) {
			return false
		}
	}
	return true
}

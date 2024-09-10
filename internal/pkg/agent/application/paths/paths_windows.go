// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

	// controlSocketRunSymlink is not created on Windows.
	controlSocketRunSymlink = ""

	// serviceName is the service name when installed.
	serviceName             = "Elastic Agent"
	serviceNameNamespaceFmt = "Elastic Agent - %s"

	// shellWrapperPath is the path to the installed shell wrapper.
	shellWrapperPath = ""

	// ShellWrapper is the wrapper that is installed.
	ShellWrapperFmt = "" // no wrapper on Windows
)

// ShellWrapperPathForNamespace is a helper to work around not being able to use fmt.Sprintf
// unconditionally since shellWrapperPath is empty on Windows.
func ShellWrapperPathForNamespace(namespace string) string {
	return ""
}

// controlSocketRunSymlinkForNamespace is a helper to work around not being able to use fmt.Sprintf
// unconditionally since controlSocketRunSymlink is empty on Windows.
func controlSocketRunSymlinkForNamespace(namespace string) string {
	return ""
}

// ArePathsEqual determines whether paths are equal taking case sensitivity of os into account.
func ArePathsEqual(expected, actual string) bool {
	return strings.EqualFold(expected, actual)
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

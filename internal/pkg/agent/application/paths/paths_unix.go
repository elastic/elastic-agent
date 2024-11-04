// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package paths

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

const ()

// shellWrapperPathForNamespace is a helper to work around not being able to use fmt.Sprintf
// unconditionally since shellWrapperPathNamespaceFmt is empty on Windows. The provided namespace is
// always lowercased for consistency.
func ShellWrapperPathForNamespace(namespace string) string {
	return fmt.Sprintf(shellWrapperPathNamespaceFmt, strings.ToLower(namespace))
}

// controlSocketRunSymlinkForNamespace is a helper to work around not being able to use fmt.Sprintf
// unconditionally since controlSocketRunSymlinkNamespaceFmt is empty on Windows.
func controlSocketRunSymlinkForNamespace(namespace string) string {
	return fmt.Sprintf(controlSocketRunSymlinkNamespaceFmt, namespace)
}

func initialControlSocketPath(topPath string) string {
	return ControlSocketFromPath(runtime.GOOS, topPath)
}

// ResolveControlSocket does nothing on non-Windows hosts.
func ResolveControlSocket(_ bool) {}

// HasPrefix tests if the path starts with the prefix.
func HasPrefix(path string, prefix string) bool {
	if path == "" || prefix == "" {
		return false
	}

	if filepath.VolumeName(path) != filepath.VolumeName(prefix) {
		return false
	}

	prefixParts := pathSplit(filepath.Clean(prefix))
	pathParts := pathSplit(filepath.Clean(path))

	if len(prefixParts) > len(pathParts) {
		return false
	}

	for i := 0; i < len(prefixParts); i++ {
		if prefixParts[i] != pathParts[i] {
			return false
		}
	}
	return true
}

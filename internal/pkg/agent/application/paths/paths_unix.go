// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package paths

import (
	"path/filepath"
	"runtime"
)

func initialControlSocketPath(topPath string) string {
	return ControlSocketFromPath(runtime.GOOS, topPath)
}

// ResolveControlSocket does nothing on non-Windows hosts.
func ResolveControlSocket() {}

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

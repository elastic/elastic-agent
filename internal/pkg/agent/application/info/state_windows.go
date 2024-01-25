// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package info

import (
<<<<<<< HEAD:internal/pkg/agent/application/info/state_windows.go
	"github.com/elastic/elastic-agent/pkg/utils"
=======
	"path/filepath"
	"runtime"
>>>>>>> 1cc6585fc0 (Windows, prevent uninstall from within installed directory (#4108)):internal/pkg/agent/application/paths/paths_unix.go
)

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	// TODO(blakerouse): Fix the market permissions on Windows.
	return nil
}
<<<<<<< HEAD:internal/pkg/agent/application/info/state_windows.go
=======

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
>>>>>>> 1cc6585fc0 (Windows, prevent uninstall from within installed directory (#4108)):internal/pkg/agent/application/paths/paths_unix.go

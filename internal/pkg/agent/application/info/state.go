// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const (
	darwin = "darwin"
)

// RunningInstalled returns true when executing Agent is the installed Agent.
//
// This verifies the running executable path based on hard-coded paths
// for each platform type.
func RunningInstalled() bool {
	expectedPaths := []string{filepath.Join(paths.InstallPath, paths.BinaryName)}
	if runtime.GOOS == darwin {
		// For the symlink on darwin the execPath is /usr/local/bin/elastic-agent
		expectedPaths = append(expectedPaths, paths.ShellWrapperPath)
	}
	execPath, _ := os.Executable()
	execPath, _ = filepath.Abs(execPath)
	execName := filepath.Base(execPath)
	execDir := filepath.Dir(execPath)
	if IsInsideData(execDir) {
		// executable path is being reported as being down inside of data path
		// move up to directories to perform the comparison
		execDir = filepath.Dir(filepath.Dir(execDir))
		if runtime.GOOS == darwin {
			execDir = filepath.Dir(filepath.Dir(filepath.Dir(execDir)))
		}
		execPath = filepath.Join(execDir, execName)
	}
	for _, expected := range expectedPaths {
		if paths.ArePathsEqual(expected, execPath) {
			return true
		}
	}
	return false
}

// IsInsideData returns true when the exePath is inside of the current Agents data path.
func IsInsideData(exePath string) bool {
	expectedPath := paths.BinaryDir(filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit())))
	return strings.HasSuffix(exePath, expectedPath)
}

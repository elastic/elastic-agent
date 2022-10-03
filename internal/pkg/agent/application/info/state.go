// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
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

	execPath = filepath.Join(paths.ExecDir(filepath.Dir(execPath)), filepath.Base(execPath))
	for _, expected := range expectedPaths {
		if paths.ArePathsEqual(expected, execPath) {
			return true
		}
	}
	return false
}

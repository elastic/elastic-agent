// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package info

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/release"
)

// RunningInstalled returns true when executing Agent is the installed Agent.
//
// This verifies the running executable path based on hard-coded paths
// for each platform type.
func RunningInstalled() bool {
	expected := filepath.Join(paths.InstallPath, paths.BinaryName)
	execPath, _ := os.Executable()
	execPath, _ = filepath.Abs(execPath)
	execName := filepath.Base(execPath)
	execDir := filepath.Dir(execPath)
	if IsInsideData(execDir) {
		// executable path is being reported as being down inside of data path
		// move up to directories to perform the comparison
		execDir = filepath.Dir(filepath.Dir(execDir))
		execPath = filepath.Join(execDir, execName)
	}
	return paths.ArePathsEqual(expected, execPath)
}

// IsInsideData returns true when the exePath is inside of the current Agents data path.
func IsInsideData(exePath string) bool {
	expectedPath := filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit()))
	return strings.HasSuffix(exePath, expectedPath)
}

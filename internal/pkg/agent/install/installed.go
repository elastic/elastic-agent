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

package install

import (
	"os"
	"path/filepath"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/application/paths"
)

// StatusType is the return status types.
type StatusType int

const (
	// NotInstalled returned when Elastic Agent is not installed.
	NotInstalled StatusType = iota
	// Installed returned when Elastic Agent is installed correctly.
	Installed
	// Broken returned when Elastic Agent is installed but broken.
	Broken
	// PackageInstall returned when the Elastic agent has been installed through a package manager (deb/rpm)
	PackageInstall
)

// Status returns the installation status of Agent.
func Status() (StatusType, string) {
	expected := filepath.Join(paths.InstallPath, paths.BinaryName)
	status, reason := checkService()
	if checkPackageInstall() {
		if status == Installed {
			return PackageInstall, "service running"
		}
		return PackageInstall, "service not running"
	}
	_, err := os.Stat(expected)
	if os.IsNotExist(err) {
		if status == Installed {
			// service installed, but no install path
			return Broken, "service exists but installation path is missing"
		}
		return NotInstalled, "no install path or service"
	}
	if status == NotInstalled {
		// install path present, but not service
		return Broken, reason
	}
	return Installed, ""
}

// checkService only checks the status of the service.
func checkService() (StatusType, string) {
	svc, err := newService()
	if err != nil {
		return NotInstalled, "unable to check service status"
	}
	status, _ := svc.Status()
	if status == service.StatusUnknown {
		return NotInstalled, "service is not installed"
	}
	return Installed, ""
}

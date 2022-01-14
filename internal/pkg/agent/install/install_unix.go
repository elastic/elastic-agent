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

// +build !windows

package install

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
)

// postInstall performs post installation for unix-based systems.
func postInstall() error {
	// do nothing
	return nil
}

func checkPackageInstall() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// NOTE searching for english words might not be a great idea as far as portability goes.
	// list all installed packages then search for paths.BinaryName?
	// dpkg is strange as the remove and purge processes leads to the package bing isted after a remove, but not after a purge

	// check debian based systems (or systems that use dpkg)
	// If the package has been installed, the status starts with "install"
	// If the package has been removed (but not pruged) status starts with "deinstall"
	// If purged or never installed, rc is 1
	if _, err := exec.Command("which", "dpkg-query").Output(); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f", "${Status}", paths.BinaryName).Output()
		if err != nil {
			return false
		}
		if strings.HasPrefix(string(out), "deinstall") {
			return false
		}
		return true
	}

	// check rhel and sles based systems (or systems that use rpm)
	// if package has been installed query retuns with a list of associated files.
	// otherwise if uninstalled, or has never been installled status ends with "not installed"
	if _, err := exec.Command("which", "rpm").Output(); err == nil {
		out, err := exec.Command("rpm", "-q", paths.BinaryName, "--state").Output()
		if err != nil {
			return false
		}
		if strings.HasSuffix(string(out), "not installed") {
			return false
		}
		return true

	}

	return false
}

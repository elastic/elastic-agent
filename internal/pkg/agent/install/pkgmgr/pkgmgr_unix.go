// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package pkgmgr

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// InstalledViaExternalPkgMgr returns true if Agent was installed with
// rpm or dep package managers
func InstalledViaExternalPkgMgr() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	binaryName := paths.BinaryName

	// NOTE searching for english words might not be a great idea as far as portability goes.
	// list all installed packages then search for paths.BinaryName?
	// dpkg is strange as the remove and purge processes leads to the package bing listed after a remove, but not after a purge

	// check debian based systems (or systems that use dpkg)
	// If the package has been installed, the status starts with "install"
	// If the package has been removed (but not purged) status starts with "deinstall"
	// If purged or never installed, rc is 1
	if _, err := exec.Command("which", "dpkg-query").Output(); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f", "${Status}", binaryName).Output()
		if err != nil {
			return false
		}
		if strings.HasPrefix(string(out), "deinstall") {
			return false
		}
		return true
	}

	// check rhel and sles based systems (or systems that use rpm)
	// if package has been installed the query will returns the list of associated files.
	// otherwise if uninstalled, or has never been installed status ends with "not installed"
	if _, err := exec.Command("which", "rpm").Output(); err == nil {
		out, err := exec.Command("rpm", "-q", binaryName, "--state").Output()
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

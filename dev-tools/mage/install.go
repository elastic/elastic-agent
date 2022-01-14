// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"github.com/elastic/elastic-agent-poc/dev-tools/mage/gotool"
)

var (
	// GoLicenserImportPath controls the import path used to install go-licenser.
	GoLicenserImportPath = "github.com/elastic/go-licenser"
)

// InstallVendored uses go get to install a command from its vendored source
func InstallVendored(importPath string) error {
	install := gotool.Install
	return install(
		install.Vendored(),
		install.Package(importPath),
	)
}

// InstallGoLicenser target installs go-licenser
func InstallGoLicenser() error {
	return gotool.Install(
		gotool.Install.Package(GoLicenserImportPath),
	)
}

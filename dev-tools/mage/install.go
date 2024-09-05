// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

var (
	// GoLicenserImportPath controls the import path used to install go-licenser.
	GoLicenserImportPath = "github.com/elastic/go-licenser"

	// GoLinkCheckImportPath controls the import path used to install the link check tool
	GoLinkCheckImportPath = "github.com/rednafi/link-patrol/cmd/link-patrol"
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

// InstallGoLinkCheck target installs the link check tool
func InstallGoLinkCheck() error {
	return gotool.Install(
		gotool.Install.Package(GoLinkCheckImportPath),
	)
}

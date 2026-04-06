// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

// GoLicenserImportPath controls the import path used to install go-licenser.
var GoLicenserImportPath = "github.com/elastic/go-licenser"

// InstallGoLicenser target installs go-licenser
func InstallGoLicenser() error {
	return gotool.Install(
		gotool.Install.Package(GoLicenserImportPath),
	)
}

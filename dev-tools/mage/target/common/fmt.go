// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import (
	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"
)

// Fmt formats source code (.go and .py) and adds license headers.
func Fmt() {
	mg.Deps(devtools.Format)
}

// AddLicenseHeaders adds license headers
func AddLicenseHeaders() {
	mg.Deps(devtools.AddLicenseHeaders)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pkg

import devtools "github.com/elastic/elastic-agent/dev-tools/mage"

// PackageTest tests the generated packages in build/distributions. It checks
// things like file ownership/mode, package attributes, etc.
func PackageTest() error {
	return devtools.TestPackages()
}

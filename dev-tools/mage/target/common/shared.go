// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import devtools "github.com/elastic/elastic-agent/dev-tools/mage"

// DumpVariables writes the template variables and values to stdout.
func DumpVariables() error {
	return devtools.DumpVariables()
}

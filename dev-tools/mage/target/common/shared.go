// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"

// DumpVariables writes the template variables and values to stdout.
func DumpVariables() error {
	return devtools.DumpVariables()
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package docs

import (
	"github.com/magefile/mage/mg"

	devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"
)

var (
	docsDeps []interface{}
)

// RegisterDeps registers dependencies of the Docs target.
func RegisterDeps(deps ...interface{}) {
	docsDeps = append(docsDeps, deps...)
}

// Docs generates the documentation for the Beat. Set PREVIEW=true to
// automatically open the browser to the docs.
func Docs() error {
	mg.SerialDeps(docsDeps...)
	return devtools.Docs.AsciidocBook()
}

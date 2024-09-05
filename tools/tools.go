// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build tools
// +build tools

// This package contains the tool dependencies of the project.

package tools

import (
	_ "github.com/magefile/mage"
	_ "github.com/tsg/go-daemon"
	_ "golang.org/x/tools/cmd/goimports"
	_ "golang.org/x/tools/cmd/stringer"
	_ "gotest.tools/gotestsum/cmd"

	_ "go.elastic.co/go-licence-detector"

	_ "github.com/rednafi/link-patrol/cmd/link-patrol"

	_ "github.com/elastic/go-licenser"
)

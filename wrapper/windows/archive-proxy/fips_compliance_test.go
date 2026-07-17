// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package main_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

const binaryPkg = "github.com/elastic/elastic-agent/wrapper/windows/archive-proxy"

func TestFIPSFullyCompliant(t *testing.T) {
	fipsscan.CheckViolations(t, binaryPkg, binaryPkg, nil, nil)
}

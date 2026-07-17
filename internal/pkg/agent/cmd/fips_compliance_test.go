// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package cmd_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

// knownViolations maps each elastic-agent component that transitively imports
// golang.org/x/crypto to the reason it is a violation. Remove an entry once
// the component no longer reaches any x/crypto package.
var knownViolations = map[string]string{
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator":               "transitively imports x/crypto/md4, x/crypto/pbkdf2, x/crypto/chacha20poly1305, x/crypto/hkdf, x/crypto/cryptobyte",
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download": "transitively imports x/crypto/openpgp (used for artifact signature verification)",
}

const (
	binaryPkg = "github.com/elastic/elastic-agent"
	rootPkg   = "github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
)

func TestFIPSFullyCompliant(t *testing.T) {
	fipsscan.CheckViolations(t, binaryPkg, rootPkg, nil, knownViolations)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fipsutils

import (
	"os"
	"strings"
	"testing"
)

type GoDebugFIPS140Value string

const (
	GoDebugFIPS140NotSet GoDebugFIPS140Value = ""
	GoDebugFIPS140On     GoDebugFIPS140Value = "on"
	GoDebugFIPS140Only   GoDebugFIPS140Value = "only"
)

// SkipIfFIPSOnly will mark the passed test as skipped if GODEBUG=fips140=only is detected.
// If GODBUG=fips140=on, go may call non-compliant algorithms and the test does not need to be skipped.
func SkipIfFIPSOnly(t *testing.T, msg string) {
	// NOTE: This only checks env var; at the time of writing fips140 can only be set via env
	// other GODEBUG settings can be set via embedded comments or in go.mod, we may need to account for this in the future.
	if GoDebugFIPS140() == GoDebugFIPS140Only {
		t.Skip("GODEBUG=fips140=only detected, skipping test:", msg)
	}
}

// GoDebugFIPS140 returns one of "on", "only", or "" depending on
// whether the GODEBUG environment variable contains fips140=on or
// fips140=only, or neither.
func GoDebugFIPS140() GoDebugFIPS140Value {
	s := os.Getenv("GODEBUG")
	if strings.Contains(s, "fips140=only") {
		return GoDebugFIPS140Only
	}
	if strings.Contains(s, "fips140=on") {
		return GoDebugFIPS140On
	}
	return GoDebugFIPS140NotSet
}

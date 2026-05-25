// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

// RuntimeComparisonIgnoredFields are fields that are expected to differ between
// documents produced by the process runtime and the OTel receiver runtime.
// Individual tests may append test-specific fields to this list.
var RuntimeComparisonIgnoredFields = []string{
	"@timestamp",
	"agent.ephemeral_id",
	"agent.id",
	"agent.version",
	"elastic_agent.id",
	"elastic_agent.snapshot",
	"elastic_agent.version",
	"event.ingested",
}

// AssertMapsEqual compares two mapstr.M documents, ignoring the specified fields,
// and fails the test if they differ.
func AssertMapsEqual(t *testing.T, m1, m2 mapstr.M, ignoredFields []string, msg string) {
	t.Helper()

	flatM1 := m1.Flatten()
	flatM2 := m2.Flatten()
	for _, f := range ignoredFields {
		// Checking ignored fields is disabled until we resolve an issue with event.ingested not being set
		// in some cases.
		// See https://github.com/elastic/elastic-agent/issues/8486 for details.
		//hasKeyM1, _ := flatM1.HasKey(f)
		//hasKeyM2, _ := flatM2.HasKey(f)
		//
		//if !hasKeyM1 && !hasKeyM2 {
		//	assert.Failf(t, msg, "ignored field %q does not exist in either map, please remove it from the ignored fields", f)
		//}
		flatM1.Delete(f)
		flatM2.Delete(f)
	}
	require.Zero(t, cmp.Diff(flatM1, flatM2), msg)
}

// AssertMapstrKeysEqual compares the keys of two mapstr.M documents, ignoring the
// specified fields, and fails the test if they have different keys.
func AssertMapstrKeysEqual(t *testing.T, m1, m2 mapstr.M, ignoredFields []string, msg string) {
	t.Helper()
	// Delete all ignored fields.
	for _, f := range ignoredFields {
		_ = m1.Delete(f)
		_ = m2.Delete(f)
	}

	flatM1 := m1.Flatten()
	flatM2 := m2.Flatten()

	for k := range flatM1 {
		flatM1[k] = ""
	}
	for k := range flatM2 {
		flatM2[k] = ""
	}

	require.Zero(t, cmp.Diff(flatM1, flatM2), msg)
}

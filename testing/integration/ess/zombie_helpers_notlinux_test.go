// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && !linux

package ess

import "testing"

func assertProcessGone(t *testing.T, pid int) {
	t.Helper()
}

func cleanupProcess(t *testing.T, pid int) {
	t.Helper()
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package storage

// On non-Windows platforms, rotate (rename) operations are not retried
// upon error.
func checkRotateErrorAndRetry(_ error, _, _ string) bool {
	return false
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package testing

// isWindowsRetryable reports whether err is a Windows error code
// that may be fixed by retrying a failed filesystem operation.
// Source: https://cs.opensource.google/go/go/+/refs/tags/go1.23.0:src/testing/testing_other.go;l=11-15
func isWindowsRetryable(err error) bool {
	return false
}

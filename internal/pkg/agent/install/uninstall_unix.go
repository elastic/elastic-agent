// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package install

func isAccessDeniedError(_ error) bool {
	return false
}

func removeBlockingExe(_ error) error {
	return nil
}

func isRetryableError(_ error) bool {
	return false
}

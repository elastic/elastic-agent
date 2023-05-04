// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !linux && !windows

package cmd

// CheckNativePlatformCompat verifies is the platform is compatible
// with the current system. This is used to check if you are trying to run a 32bits
// binary on a 64 bits system.
func CheckNativePlatformCompat() error {
	return nil
}

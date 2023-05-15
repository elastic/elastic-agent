// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package utils

// HasStrictExecPerms ensures that the path is executable by the owner and that the owner of the file
// is the same as the UID or root.
func HasStrictExecPerms(path string, uid int) error {
	// TODO: Need to add check on Windows to ensure that the ACL are correct for the binary before execution.
	return nil
}

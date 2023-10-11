// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

// FixPermissions fixes the permissions on the installed system.
func FixPermissions(topPath string, uid string, gid string) error {
	return fixPermissions(topPath, uid, gid)
}

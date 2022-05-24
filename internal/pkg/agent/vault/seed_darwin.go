// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin
// +build darwin

package vault

// DisableRootCheck noop on darwin to allow to compile the common code
// Noop on darwin
func DisableRootCheck() {
}

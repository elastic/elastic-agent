// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package paths

import (
	"runtime"
)

func initialControlSocketPath(topPath string) string {
	return ControlSocketFromPath(runtime.GOOS, topPath)
}

// ResolveControlSocket does nothing on non-Windows hosts.
func ResolveControlSocket() {}

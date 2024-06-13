// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package cmd

// logExternal logs the error to an external log.  On non-windows systems this is a no-op.
func logExternal(msg string) {
}

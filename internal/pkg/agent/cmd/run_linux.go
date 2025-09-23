// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package cmd

import "github.com/elastic/elastic-agent/pkg/utils"

// logExternal logs the error to an external log.  On non-windows systems this is a no-op.
func logExternal(msg string) {
}

func getDesiredUser() (string, string, error) { return "", "", nil }

func dropRootPrivileges(ownership utils.FileOwner) error { return nil }

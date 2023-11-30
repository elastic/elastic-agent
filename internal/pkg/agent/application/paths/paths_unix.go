// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package paths

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

const (
	// ControlSocketName is the control socket name.
	ControlSocketName = "elastic-agent.sock"
)

func initialControlSocketPath(topPath string) string {
	path := fmt.Sprintf("unix://%s", filepath.Join(topPath, ControlSocketName))
	if len(path) < 104 {
		return path
	}
	// place in global /tmp to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(path)))
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package control

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// Address returns the address to connect to Elastic Agent daemon.
func Address() string {
	return paths.ControlSocket()
}

// AddressFromPath returns the connection address for an Elastic Agent running on the defined platform, and its
// executing directory.
func AddressFromPath(platform string, path string) (string, error) {
	// elastic-agent will always derive the path to the socket using an absolute path
	absDir, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path of %s: %w", path, err)
	}
	// elastic-agent is given a path from the OS that removes all symlinks, without then
	// the path to the socket will not be the same.
	noSyms, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate all symlinks of %s: %w", absDir, err)
	}
	// socket should be inside this directory
	socketPath := filepath.Join(noSyms, paths.ControlSocketName)
	if platform == "windows" {
		// on windows the control socket is always at the sha256 of the socketPath
		return fmt.Sprintf(`\\.\pipe\elastic-agent-%x`, sha256.Sum256([]byte(socketPath))), nil
	}
	unixSocket := fmt.Sprintf("unix://%s", socketPath)
	if len(unixSocket) < 104 {
		// small enough to fit
		return unixSocket, nil
	}
	// place in global /tmp to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(socketPath))), nil
}

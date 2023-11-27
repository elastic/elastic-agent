// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/elastic/elastic-agent/version"
)

// postInstall performs post installation for Windows systems.
func postInstall(topPath string) error {
	// delete the top-level elastic-agent.exe
	binary := filepath.Join(topPath, paths.BinaryName)
	err := os.Remove(binary)
	if err != nil {
		// do not handle does not exist, it should have existed
		return err
	}

	// since we removed the top-level elastic-agent.exe we can get
	// rid of the package version file (it was there only in case
	// the top .exe was called with a `version` subcommand )
	err = os.Remove(filepath.Join(topPath, version.PackageVersionFileName))
	if err != nil {
		// do not handle does not exist, it should have existed
		return err
	}

	// create top-level symlink to nested binary
	realBinary := filepath.Join(topPath, "data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit()), paths.BinaryName)
	err = os.Symlink(realBinary, binary)
	if err != nil {
		return err
	}

	return nil
}

// createSocketDir creates the socket directory.
func createSocketDir(ownership utils.FileOwner) error {
	// doesn't do anything on windows, no directory is needed.
	return nil
}

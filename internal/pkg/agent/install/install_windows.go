// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/elastic/elastic-agent/version"
)

const (
	passwordLength = 127 // maximum length allowed by Windows
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

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	return FixPermissions(markerFilePath, ownership)
}

// withServiceOptions just sets the user/group for the service.
func withServiceOptions(username string, groupName string) ([]serviceOpt, error) {
	if username == "" {
		// not installed with --unprivileged; nothing to do
		return []serviceOpt{}, nil
	}

	// service requires a password to launch as the user
	// this sets it to a random password that is only known by the service
	password := randomPassword(passwordLength)
	err := SetUserPassword(username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to set user %s password for service: %w", username, err)
	}

	// username must be prefixed with the domain for the CreateServiceW call to work
	// we are always working on the local machine so the hostname of the machine is used
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	username = fmt.Sprintf(`%s\%s`, hostname, username)
	return []serviceOpt{withUserGroup(username, groupName), withPassword(password)}, nil
}

func randomPassword(length int) string {
	runes := []rune("abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteRune(runes[rand.Intn(len(runes))])
	}
	return sb.String()
}

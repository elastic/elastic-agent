// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestIsUpgradeable(t *testing.T) {
	//default behavior is to return false, since the `allowUpgradable` build flag isn't set
	upgradable := IsUpgradeable()
	require.False(t, upgradable)

	// fake a positive result for IsUpgradeable()
	tempTop := t.TempDir()
	paths.SetTop(tempTop)
	err := createInstallMarker(tempTop, utils.CurrentFileOwner())
	require.NoError(t, err)
	SupervisorPid = os.Getppid()

	upgradable = IsUpgradeable()
	require.True(t, upgradable)
}

func TestRunningUnderSupervisor(t *testing.T) {
	SupervisorPid = os.Getppid()
	under := RunningUnderSupervisor()
	require.True(t, under)
}

// taken from the install.go file, which we cannot import due to a cyclical import
func createInstallMarker(topPath string, ownership utils.FileOwner) error {
	markerFilePath := filepath.Join(topPath, paths.MarkerFileName)
	if _, err := os.Create(markerFilePath); err != nil {
		return err
	}
	return nil
}

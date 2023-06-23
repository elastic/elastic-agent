// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"

	"github.com/stretchr/testify/require"
)

func TestInstallWithoutBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(context.Background())
	require.NoError(t, err)

	// Check that default base path is clean
	var defaultBasePath string
	switch runtime.GOOS {
	case "darwin":
		defaultBasePath = `/Library`
	case "linux":
		defaultBasePath = `/opt`
	case "windows":
		defaultBasePath = `C:\Program Files`
	}

	topPath := filepath.Join(defaultBasePath, "Elastic", "Agent")
	_, err = os.Stat(topPath)
	require.True(t, os.IsNotExist(err))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	_, err = fixture.Install(context.Background(), &atesting.InstallOpts{Force: true})
	require.NoError(t, err)

	// Check that Agent was installed in default base path
	checkInstallSuccess(t, topPath)
	t.Run("check agent package version", testAgentPackageVersion(context.Background(), fixture, true))
}

func TestInstallWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(context.Background())
	require.NoError(t, err)

	// The `--base-path` flag is defined for the `elastic-agent install` CLI sub-command BUT
	// it is hidden (see https://github.com/elastic/elastic-agent/pull/2592).  So we validate
	// here that the usage text for the `install` sub-command does NOT mention the `--base-path`
	// flag in it.
	const basePathFlag = "--base-path"
	output, err := fixture.Exec(context.Background(), []string{"help", "install"})
	require.NoError(t, err)
	require.NotContains(t, string(output), basePathFlag)

	// Set up random temporary directory to serve as base path for Elastic Agent
	// installation.
	tmpDir := t.TempDir()
	randomBasePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	_, err = fixture.Install(context.Background(), &atesting.InstallOpts{
		BasePath: randomBasePath,
		Force:    true,
	})
	require.NoError(t, err)

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(randomBasePath, "Elastic", "Agent")
	checkInstallSuccess(t, topPath)
	t.Run("check agent package version", testAgentPackageVersion(context.Background(), fixture, true))
}

func checkInstallSuccess(t *testing.T, topPath string) {
	t.Helper()
	_, err := os.Stat(topPath)
	require.NoError(t, err)

	// Check that a few expected installed files are present
	installedBinPath := filepath.Join(topPath, "elastic-agent")
	installedDataPath := filepath.Join(topPath, "data")
	installMarkerPath := filepath.Join(topPath, ".installed")

	_, err = os.Stat(installedBinPath)
	require.NoError(t, err)
	_, err = os.Stat(installedDataPath)
	require.NoError(t, err)
	_, err = os.Stat(installMarkerPath)
	require.NoError(t, err)
}

func randStr(length int) string {
	rand.Seed(time.Now().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	runes := make([]rune, length)
	for i := range runes {
		runes[i] = letters[rand.Intn(len(letters))]
	}

	return string(runes)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"

	"github.com/stretchr/testify/require"
)

func TestInstallWithoutBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
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

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
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
	err = os.RemoveAll(topPath)
	require.NoError(t, err, "failed to remove %q. The test requires this path not to exist.")

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	out, err := fixture.Install(ctx, &atesting.InstallOpts{Force: true})
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path
	checkInstallSuccess(t, topPath)
	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	// Make sure uninstall from within the topPath fails on Windows
	if runtime.GOOS == "windows" {
		cwd, err := os.Getwd()
		require.NoErrorf(t, err, "GetWd failed: %s", err)
		err = os.Chdir(topPath)
		require.NoErrorf(t, err, "Chdir to topPath failed: %s", err)
		t.Cleanup(func() {
			_ = os.Chdir(cwd)
		})
		out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.Error(t, err, "uninstall should have failed")
		require.Containsf(t, string(out), "uninstall must be run from outside the installed path", "expected error string not found in: %s err: %s", out, err)
	}

}

func TestInstallWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
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

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// Set up random temporary directory to serve as base path for Elastic Agent
	// installation.
	tmpDir := t.TempDir()
	randomBasePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	out, err := fixture.Install(ctx, &atesting.InstallOpts{
		BasePath: randomBasePath,
		Force:    true,
	})
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(randomBasePath, "Elastic", "Agent")
	checkInstallSuccess(t, topPath)
	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	// Make sure uninstall from within the topPath fails on Windows
	if runtime.GOOS == "windows" {
		cwd, err := os.Getwd()
		require.NoErrorf(t, err, "GetWd failed: %s", err)
		err = os.Chdir(topPath)
		require.NoErrorf(t, err, "Chdir to topPath failed: %s", err)
		t.Cleanup(func() {
			_ = os.Chdir(cwd)
		})
		out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.Error(t, err, "uninstall should have failed")
		require.Containsf(t, string(out), "uninstall must be run from outside the installed path", "expected error string not found in: %s err: %s", out, err)
	}
}

<<<<<<< HEAD
func checkInstallSuccess(t *testing.T, topPath string) {
=======
// TestRepeatedInstallUninstall will install then uninstall the agent
// repeatedly.  This test exists because of a number of race
// conditions that have occurred in the uninstall process.  Current
// testing shows each iteration takes around 16 seconds.
func TestRepeatedInstallUninstall(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	maxRunTime := 2 * time.Minute
	iterations := 100
	for i := 0; i < iterations; i++ {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), i), func(t *testing.T) {

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
			// Get path to Elastic Agent executable
			fixture, err := define.NewFixture(t, define.Version())
			require.NoError(t, err)

			ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(maxRunTime))
			defer cancel()

			// Prepare the Elastic Agent so the binary is extracted and ready to use.
			err = fixture.Prepare(ctx)
			require.NoError(t, err)

			// Run `elastic-agent install`.  We use `--force` to prevent interactive
			// execution.
			opts := &atesting.InstallOpts{Force: true}
			out, err := fixture.Install(ctx, opts)
			if err != nil {
				t.Logf("install output: %s", out)
				require.NoError(t, err)
			}

			// Check that Agent was installed in default base path
			checkInstallSuccess(t, topPath, opts.IsUnprivileged(runtime.GOOS))
			t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
			out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
			require.NoErrorf(t, err, "uninstall failed: %s", err)
		})
	}
}

func checkInstallSuccess(t *testing.T, topPath string, unprivileged bool) {
>>>>>>> 82efe133d0 ([uninstall] ensure service is stopped on windows (#4224))
	t.Helper()
	_, err := os.Stat(topPath)
	require.NoError(t, err)

	// Check that a few expected installed files are present
	installedBinPath := filepath.Join(topPath, exeOnWindows("elastic-agent"))
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

func exeOnWindows(filename string) string {
	if runtime.GOOS == define.Windows {
		return filename + ".exe"
	}
	return filename
}

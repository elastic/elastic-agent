// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
)

func TestInstallWithoutBasePath(t *testing.T) {
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
	opts := &atesting.InstallOpts{Force: true}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path
	checkInstallSuccess(t, topPath, opts.IsUnprivileged(runtime.GOOS))
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
		// `elastic-agent install` (even though it will
		// be installed as non-root).
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
	basePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{
		BasePath: basePath,
		Force:    true,
	}
	if opts.IsUnprivileged(runtime.GOOS) {
		switch runtime.GOOS {
		case define.Linux:
			// When installing with unprivileged using a base path the
			// base needs to be accessible by the `elastic-agent` user that will be
			// executing the process, but is not created yet. Using a base that exists
			// and is known to be accessible by standard users, ensures this tests
			// works correctly and will not hit a permission issue when spawning the
			// elastic-agent service.
			basePath = `/usr`
		default:
			t.Fatalf("only Linux supports unprivileged mode")
		}
		opts.BasePath = basePath
	}

	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	checkInstallSuccess(t, topPath, opts.IsUnprivileged(runtime.GOOS))
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

func checkInstallSuccess(t *testing.T, topPath string, unprivileged bool) {
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

	if unprivileged {
		// Specific checks depending on the platform.
		checkPlatformUnprivileged(t, topPath)

		// Executing `elastic-agent status` as the `elastic-agent` user should work.
		var output []byte
		require.Eventuallyf(t, func() bool {
			cmd := exec.Command("sudo", "-u", "elastic-agent", "elastic-agent", "status")
			output, err = cmd.CombinedOutput()
			return err == nil
		}, 3*time.Minute, 1*time.Second, "status never successful: %s (output: %s)", err, output)

		// Executing `elastic-agent status` as the original user should fail, because that
		// user is not in the 'elastic-agent' group.
		originalUser := os.Getenv("SUDO_USER")
		if originalUser != "" {
			cmd := exec.Command("sudo", "-u", originalUser, "elastic-agent", "status")
			output, err := cmd.CombinedOutput()
			require.Error(t, err, "running sudo -u %s elastic-agent status should have failed: %s", originalUser, output)
		}
	}
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

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration && !windows

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestInstallUnprivilegedWithoutBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,

		// Only supports Linux at the moment.
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
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
	err = os.RemoveAll(topPath)
	require.NoError(t, err, "failed to remove %q. The test requires this path not to exist.")

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	out, err := fixture.Install(context.Background(), &atesting.InstallOpts{Force: true, Unprivileged: true})
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	checkInstallUnprivilegedSuccess(t, topPath)
}

func TestInstallUnprivilegedWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,

		// Only supports Linux at the moment.
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(context.Background())
	require.NoError(t, err)

	// Other test `TestInstallWithBasePath` uses a random directory for the base
	// path and that works because its running root. When using a base path the
	// base needs to be accessible by the `elastic-agent` user that will be
	// executing the process, but is not created yet. Using a base that exists
	// and is known to be accessible by standard users, ensures this tests
	// works correctly and will not hit a permission issue when spawning the
	// elastic-agent service.
	var basePath string
	switch runtime.GOOS {
	case define.Linux:
		// default is `/opt`
		basePath = `/usr`
	default:
		t.Fatalf("only Linux is supported by this test; should have been skipped")
	}

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	out, err := fixture.Install(context.Background(), &atesting.InstallOpts{
		BasePath:     basePath,
		Force:        true,
		Unprivileged: true,
	})
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	checkInstallUnprivilegedSuccess(t, topPath)
}

func checkInstallUnprivilegedSuccess(t *testing.T, topPath string) {
	t.Helper()

	// Check that the elastic-agent user/group exist.
	uid, err := install.FindUID("elastic-agent")
	require.NoError(t, err)
	gid, err := install.FindGID("elastic-agent")
	require.NoError(t, err)

	// Path should now exist as well as be owned by the correct user/group.
	info, err := os.Stat(topPath)
	require.NoError(t, err)
	fs, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equalf(t, fs.Uid, uint32(uid), "%s not owned by elastic-agent user", topPath)
	require.Equalf(t, fs.Gid, uint32(gid), "%s not owned by elastic-agent group", topPath)

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

	// Check that the socket is created with the correct permissions.
	socketPath := strings.TrimPrefix(paths.ControlSocketUnprivilegedPath, "unix://")
	require.Eventuallyf(t, func() bool {
		_, err = os.Stat(socketPath)
		return err == nil
	}, 3*time.Minute, 1*time.Second, "%s socket never created: %s", socketPath, err)
	info, err = os.Stat(socketPath)
	require.NoError(t, err)
	fs, ok = info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equalf(t, fs.Uid, uint32(uid), "%s not owned by elastic-agent user", socketPath)
	require.Equalf(t, fs.Gid, uint32(gid), "%s not owned by elastic-agent group", socketPath)

	// Executing `elastic-agent status` as the `elastic-agent` user should work.
	var output []byte
	require.Eventuallyf(t, func() bool {
		cmd := exec.Command("sudo", "-u", "elastic-agent", "elastic-agent", "status")
		output, err = cmd.CombinedOutput()
		return err == nil
	}, 3*time.Minute, 1*time.Second, "status never successful: %s (output: %s)", err, output)

	// Executing `elastic-agent status` as the original user should fail, because that
	// user is not in the 'elastic-agent' group.
	originalUser := os.Getenv("USER")
	if originalUser != "" {
		cmd := exec.Command("sudo", "-u", originalUser, "elastic-agent", "status")
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "running elastic-agent status should have failed: %s", output)
	}
}

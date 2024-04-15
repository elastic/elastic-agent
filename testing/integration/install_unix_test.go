// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration && !windows

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func checkPlatformUnprivileged(t *testing.T, _ *atesting.Fixture, topPath string) {
	// Check that the elastic-agent user/group exist.
	uid, err := install.FindUID(install.ElasticUsername)
	require.NoError(t, err)
	gid, err := install.FindGID(install.ElasticGroupName)
	require.NoError(t, err)

	// Path should now exist as well as be owned by the correct user/group.
	info, err := os.Stat(topPath)
	require.NoError(t, err)
	fs, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equalf(t, fs.Uid, uint32(uid), "%s not owned by %s user", install.ElasticUsername, topPath)
	require.Equalf(t, fs.Gid, uint32(gid), "%s not owned by %s group", install.ElasticGroupName, topPath)

	// Check that the socket is created with the correct permissions.
	socketPath := filepath.Join(topPath, paths.ControlSocketName)
	require.Eventuallyf(t, func() bool {
		_, err = os.Stat(socketPath)
		return err == nil
	}, 3*time.Minute, 1*time.Second, "%s socket never created: %s", socketPath, err)
	info, err = os.Stat(socketPath)
	require.NoError(t, err)
	fs, ok = info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equalf(t, fs.Uid, uint32(uid), "%s not owned by %s user", install.ElasticUsername, socketPath)
	require.Equalf(t, fs.Gid, uint32(gid), "%s not owned by %s group", install.ElasticGroupName, socketPath)

	// Executing `elastic-agent status` as the `elastic-agent-user` user should work.
	var output []byte
	require.Eventuallyf(t, func() bool {
		cmd := exec.Command("sudo", "-u", install.ElasticUsername, "elastic-agent", "status")
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

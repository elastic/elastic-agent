// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration && !windows

package integration

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
)

func checkPlatformUnprivileged(t *testing.T, topPath string) {
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
	require.Equalf(t, fs.Uid, uint32(uid), "%s not owned by elastic-agent user", socketPath)
	require.Equalf(t, fs.Gid, uint32(gid), "%s not owned by elastic-agent group", socketPath)
}

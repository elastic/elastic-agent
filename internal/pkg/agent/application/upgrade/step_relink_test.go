// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLiveVersionedHome exercises the helper against a real install layout for
// the host OS. createFakeAgentInstall + createLink build the on-disk structure
// using paths.BinaryPath, so on darwin CI this is a real darwin test (the
// .app/Contents/MacOS bundle is created and resolved); on linux/windows CI it
// covers the flat layout. If paths.BinaryPath ever changes its layout on a
// platform without a corresponding update to liveVersionedHome, this test will
// fail on that platform's CI.
func TestLiveVersionedHome(t *testing.T) {
	t.Run("symlink points at versioned-home binary", func(t *testing.T) {
		topDir := t.TempDir()
		versionedHome := createFakeAgentInstall(t, topDir, "1.2.3", "abcdef", true)
		createLink(t, topDir, versionedHome)

		got, err := liveVersionedHome(topDir)
		require.NoError(t, err)
		expected, err := filepath.Rel(topDir, filepath.Join(topDir, versionedHome))
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})

	t.Run("missing symlink returns error", func(t *testing.T) {
		topDir := t.TempDir()
		_, err := liveVersionedHome(topDir)
		require.Error(t, err)
	})

	t.Run("symlink resolving outside topDir returns error", func(t *testing.T) {
		topDir := t.TempDir()
		// Place the binary in a separate temp dir so the symlink resolves
		// outside topDir. liveVersionedHome must reject the result rather
		// than returning a "../<other>" relative path that would let cleanup
		// reason about a directory it doesn't own.
		outsideDir := t.TempDir()
		binary := filepath.Join(outsideDir, AgentName)
		require.NoError(t, os.WriteFile(binary, nil, 0o755))
		require.NoError(t, os.Symlink(binary, filepath.Join(topDir, AgentName)))

		_, err := liveVersionedHome(topDir)
		require.Error(t, err)
	})
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func agentExecutableForTest() string {
	name := agentName
	if runtime.GOOS == windows {
		name += exe
	}
	return name
}

// writeFakeAgentBinary creates a directory tree mirroring a real install and
// writes a placeholder binary at the BinaryPath, returning the bare (no .exe)
// path the caller should pass to changeSymlink.
func writeFakeAgentBinary(t *testing.T, topDir, versionedHomeRel string) string {
	t.Helper()

	absVersionedHome := filepath.Join(topDir, versionedHomeRel)
	require.NoError(t, os.MkdirAll(paths.BinaryPath(absVersionedHome, ""), 0o750))

	binPath := paths.BinaryPath(absVersionedHome, agentExecutableForTest())
	require.NoError(t, os.WriteFile(binPath, []byte("fake agent binary"), 0o750))

	return paths.BinaryPath(absVersionedHome, agentName)
}

func TestChangeSymlinkHappyPath(t *testing.T) {
	topDir := t.TempDir()
	log := newErrorLogger(t)

	newTarget := writeFakeAgentBinary(t, topDir, filepath.Join("data", "elastic-agent-1.2.3-abcdef"))
	symlinkPath := filepath.Join(topDir, agentName)

	require.NoError(t, changeSymlink(log, topDir, symlinkPath, newTarget))

	livePath := filepath.Join(topDir, agentExecutableForTest())
	linkTarget, err := os.Readlink(livePath)
	require.NoError(t, err, "live symlink must exist after rotation")

	expected := newTarget
	if runtime.GOOS == windows {
		expected += exe
	}
	assert.Equal(t, expected, linkTarget)

	// staging symlink should not linger after a successful rotation
	assert.NoFileExists(t, prevSymlinkPath(topDir))
}

func TestChangeSymlinkRefusesNonExistentTarget(t *testing.T) {
	topDir := t.TempDir()
	log := newErrorLogger(t)

	newTarget := paths.BinaryPath(filepath.Join(topDir, "data", "elastic-agent-deleted"), agentName)
	symlinkPath := filepath.Join(topDir, agentName)

	err := changeSymlink(log, topDir, symlinkPath, newTarget)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to rotate")
	assert.Contains(t, err.Error(), "non-existent target")

	// no symlink should have been created at the live path
	livePath := filepath.Join(topDir, agentExecutableForTest())
	_, statErr := os.Lstat(livePath)
	assert.True(t, errors.Is(statErr, fs.ErrNotExist), "live symlink must not be created when target is missing, got err=%v", statErr)

	// nor should a staging symlink have been left behind
	_, statErr = os.Lstat(prevSymlinkPath(topDir))
	assert.True(t, errors.Is(statErr, fs.ErrNotExist), "staging symlink must not be created when target is missing, got err=%v", statErr)
}

// TestChangeSymlinkRotatesOverStalePrev ensures that a leftover staging
// symlink from a prior interrupted rotation does not cause changeSymlink to
// silently no-op. The pre-fix code did `if !os.IsNotExist(err) { return err }`
// on the os.Remove of the staging path: when the Remove succeeded (err == nil),
// !os.IsNotExist(nil) was true and the function returned nil without rotating.
func TestChangeSymlinkRotatesOverStalePrev(t *testing.T) {
	topDir := t.TempDir()
	log := newErrorLogger(t)

	newTarget := writeFakeAgentBinary(t, topDir, filepath.Join("data", "elastic-agent-1.2.3-abcdef"))
	symlinkPath := filepath.Join(topDir, agentName)

	// pre-create a leftover .prev staging symlink pointing nowhere meaningful
	stalePrev := prevSymlinkPath(topDir)
	require.NoError(t, os.Symlink(filepath.Join(topDir, "nonexistent-stale-target"), stalePrev))
	_, err := os.Lstat(stalePrev)
	require.NoError(t, err, "stale staging symlink must exist before the call")

	require.NoError(t, changeSymlink(log, topDir, symlinkPath, newTarget))

	livePath := filepath.Join(topDir, agentExecutableForTest())
	linkTarget, err := os.Readlink(livePath)
	require.NoError(t, err, "live symlink must exist after rotation")

	expected := newTarget
	if runtime.GOOS == windows {
		expected += exe
	}
	assert.Equal(t, expected, linkTarget, "live symlink must point at the new target, not the stale staging path")

	// staging symlink should not linger after a successful rotation
	_, statErr := os.Lstat(stalePrev)
	assert.True(t, errors.Is(statErr, fs.ErrNotExist), "staging symlink must not linger after rotation, got err=%v", statErr)
}

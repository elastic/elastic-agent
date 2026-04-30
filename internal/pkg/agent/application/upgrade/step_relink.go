// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	windowsOSName = "windows"
	darwinOSName  = "darwin"
	exe           = ".exe"
)

func changeSymlink(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error {

	// handle windows suffixes
	if runtime.GOOS == windowsOSName {
		symlinkPath += exe
		newTarget += exe
	}

	prevNewPath := prevSymlinkPath(topDirPath)
	log.Infow("Changing symlink", "symlink_path", symlinkPath, "new_path", newTarget, "prev_path", prevNewPath)

	// remove symlink to avoid upgrade failures
	if err := os.Remove(prevNewPath); !os.IsNotExist(err) {
		return err
	}

	if err := os.Symlink(newTarget, prevNewPath); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to update agent symlink")
	}

	// safely rotate
	return file.SafeFileRotate(symlinkPath, prevNewPath)
}

func prevSymlinkPath(topDirPath string) string {
	agentPrevName := AgentName + ".prev"

	// handle windows suffixes
	if runtime.GOOS == windowsOSName {
		agentPrevName = AgentName + ".exe.prev"
	}

	return filepath.Join(topDirPath, agentPrevName)
}

// liveVersionedHome resolves the versioned home that the top-level agent
// symlink points at, returned as a path relative to topDirPath. Used by
// cleanup as a defense against stale keep lists deleting the live install
// (https://github.com/elastic/elastic-agent/issues/13505).
//
// Returns the empty string and a non-nil error if the symlink can't be read
// or doesn't resolve to a path under topDirPath.
func liveVersionedHome(topDirPath string) (string, error) {
	symlinkPath := filepath.Join(topDirPath, AgentName)
	if runtime.GOOS == windowsOSName {
		symlinkPath += exe
	}
	target, err := os.Readlink(symlinkPath)
	if err != nil {
		return "", fmt.Errorf("reading symlink %q: %w", symlinkPath, err)
	}
	// Resolve a relative symlink target against the symlink's directory.
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(symlinkPath), target)
	}
	// target is the binary path; strip down to the versioned home.
	// On macOS, paths.BinaryPath produces an extra three nested directories
	// (<versionedHome>/elastic-agent.app/Contents/MacOS/elastic-agent), so
	// we strip those levels to recover the versioned home.
	home := filepath.Dir(target)
	if runtime.GOOS == darwinOSName {
		home = filepath.Dir(filepath.Dir(filepath.Dir(home)))
	}
	rel, err := filepath.Rel(topDirPath, home)
	if err != nil {
		return "", fmt.Errorf("computing %q relative to %q: %w", home, topDirPath, err)
	}
	// filepath.Rel is purely lexical and happily returns "../foo" when home
	// is outside topDirPath. Enforce the documented contract here so callers
	// (cleanup's keep list) never get a path that traverses out of the data
	// dir, which could let a malicious or corrupt symlink redirect cleanup
	// decisions.
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("symlink target %q resolves outside top directory %q", home, topDirPath)
	}
	return rel, nil
}

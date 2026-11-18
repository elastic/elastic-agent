// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// inactiveBuildsToKeep is the number of the most recently written inactive builds whose logs are kept,
// in addition to the logs of the running build.
const inactiveBuildsToKeep = 1

type buildLogsDir struct {
	path    string
	modTime time.Time
}

// CleanupBuildLogs removes the log directories of old builds from logsRoot.
//
// It keeps the directory of the running build (currentDirName) and the inactiveBuildsToKeep most recently
// written inactive build directories. Everything else that looks like a build directory is removed.
// Links are never followed: a link in place of a build directory is ignored, one inside a build directory is
// removed together with it, and a link, or anything that is not a directory, in place of logsRoot makes the whole cleanup fail.
// A directory that cannot be removed does not stop the others; the failures are returned joined. Windows can
// refuse to remove a file that another process still has open, so the removal is retried for a while. It stops when
// ctx is done, which is not reported as an error: what is left is removed by the next cleanup.
func CleanupBuildLogs(ctx context.Context, log *logger.Logger, logsRoot, currentDirName string) error {
	// a link in place of the logs root could make the cleanup remove directories somewhere else, and so could
	// anything else that is not a plain directory, such as a junction on Windows
	if info, err := os.Lstat(logsRoot); err == nil && info.Mode().Type() != fs.ModeDir {
		return fmt.Errorf("logs root %q is not a directory but a link or something else, not cleaning it", logsRoot)
	}

	entries, err := os.ReadDir(logsRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading logs root %q: %w", logsRoot, err)
	}

	var inactive []buildLogsDir
	for _, e := range entries {
		if !e.IsDir() || e.Name() == currentDirName || !paths.IsBuildLogsDirName(e.Name()) {
			continue
		}
		p := filepath.Join(logsRoot, e.Name())
		inactive = append(inactive, buildLogsDir{path: p, modTime: lastWrite(p)})
	}
	if len(inactive) <= inactiveBuildsToKeep {
		return nil
	}

	// most recently written first, ties broken by path to be deterministic; the first ones are kept
	slices.SortFunc(inactive, func(a, b buildLogsDir) int {
		if c := b.modTime.Compare(a.modTime); c != 0 {
			return c
		}
		return cmp.Compare(b.path, a.path)
	})

	var errs []error
	for _, d := range inactive[inactiveBuildsToKeep:] {
		// stop when asked to, what is left is removed by the next cleanup
		if err := ctx.Err(); err != nil {
			log.Debugf("Stopped cleaning the build logs: %s", err)
			break
		}
		log.Infof("Removing the logs of the old build %q", d.path)
		if err := install.RemovePath(ctx, log, d.path); err != nil {
			errs = append(errs, fmt.Errorf("removing %q: %w", d.path, err))
		}
	}
	return errors.Join(errs...)
}

// lastWrite returns the most recent modification time of any regular file below dir.
// It is best effort: entries that cannot be read, for example because rotation removed them, are skipped.
// Directory times are ignored, they change on rotation, not on writes. The time of a file is read from the file,
// not from the directory listing, which can be out of date for a file that is still open on Windows.
func lastWrite(dir string) time.Time {
	var latest time.Time
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best effort, an entry that cannot be read is skipped
		}
		// only regular files count: a link is not a log, and its own time is the time it was created
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := os.Lstat(path); err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest
}

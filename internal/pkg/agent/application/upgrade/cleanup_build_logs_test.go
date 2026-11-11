// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// ago returns a pointer to d, for the optional times of the scenarios.
func ago(d time.Duration) *time.Duration { return &d }

func TestCleanupBuildLogs(t *testing.T) {
	const defaultCurrent = "9.4.0-aaaaaa"

	// build is a build log directory of a scenario
	type build struct {
		name string
		// age is how long ago the newest file of the build was written, a build without logs is empty
		age   time.Duration
		empty bool
		// dirAge is how long ago the directory was last modified, it is the creation time if not set
		dirAge *time.Duration
	}

	tests := []struct {
		name string
		// current is the name of the running build, defaultCurrent if not set
		current string
		builds  []build
		// files are files created directly in the logs root
		files []string
		// kept and removed are the directories that must exist and must not exist after the cleanup
		kept    []string
		removed []string
		// noRoot runs the cleanup without a logs root
		noRoot bool
	}{
		{
			name:    "keeps the running build and the latest inactive one",
			builds:  []build{{name: defaultCurrent}, {name: "9.3.0-bbbbbb", age: 3 * time.Hour}, {name: "9.3.1-cccccc", age: time.Hour}, {name: "9.2.0-dddddd", age: 5 * time.Hour}},
			kept:    []string{defaultCurrent, "9.3.1-cccccc"},
			removed: []string{"9.3.0-bbbbbb", "9.2.0-dddddd"},
		},
		{
			name:    "keeps the running build even when it was written least recently",
			builds:  []build{{name: defaultCurrent, age: 5 * time.Hour}, {name: "9.3.0-bbbbbb", age: 2 * time.Hour}, {name: "9.3.1-cccccc", age: time.Hour}},
			kept:    []string{defaultCurrent, "9.3.1-cccccc"},
			removed: []string{"9.3.0-bbbbbb"},
		},
		{
			name:    "prefers a build with logs over an empty one",
			builds:  []build{{name: defaultCurrent}, {name: "9.3.0-bbbbbb", age: 3 * time.Hour}, {name: "9.3.1-cccccc", empty: true}},
			kept:    []string{defaultCurrent, "9.3.0-bbbbbb"},
			removed: []string{"9.3.1-cccccc"},
		},
		{
			name:    "keeps the build with the greater name of two builds written at the same time",
			builds:  []build{{name: defaultCurrent}, {name: "9.3.0-bbbbbb", age: time.Hour}, {name: "9.3.1-cccccc", age: time.Hour}},
			kept:    []string{defaultCurrent, "9.3.1-cccccc"},
			removed: []string{"9.3.0-bbbbbb"},
		},
		{
			name: "keeps the build that was written last, not the one that was created last",
			builds: []build{
				{name: defaultCurrent},
				// created long ago, its logs were written most recently
				{name: "9.3.0-bbbbbb", age: time.Hour, dirAge: ago(10 * time.Hour)},
				// created most recently, for example in advance, its logs are older
				{name: "9.3.1-cccccc", age: 5 * time.Hour, dirAge: ago(0)},
			},
			kept:    []string{defaultCurrent, "9.3.0-bbbbbb"},
			removed: []string{"9.3.1-cccccc"},
		},
		{
			name:    "handles builds named after the commit only",
			current: "aaaaaa",
			builds:  []build{{name: "aaaaaa"}, {name: "bbbbbb", age: 3 * time.Hour}, {name: "9.3.0-cccccc", age: time.Hour}, {name: "dddddd", age: 5 * time.Hour}},
			kept:    []string{"aaaaaa", "9.3.0-cccccc"},
			removed: []string{"bbbbbb", "dddddd"},
		},
		{
			name: "does not touch entries that are not builds",
			builds: []build{
				{name: defaultCurrent},
				{name: "9.3.0-bbbbbb", age: time.Hour},
				// with two inactive builds the cleanup removes the older one, which must not affect anything else
				{name: "9.2.1-eeeeee", age: 3 * time.Hour},
				{name: "custom", age: 10 * time.Hour},
			},
			// a file named like a build is not a build directory
			files:   []string{"elastic-agent-custom.ndjson", "9.2.0-dddddd"},
			kept:    []string{defaultCurrent, "9.3.0-bbbbbb", "custom"},
			removed: []string{"9.2.1-eeeeee"},
		},
		{
			name:   "does nothing without a logs root",
			noRoot: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			current := tc.current
			if current == "" {
				current = defaultCurrent
			}
			root := filepath.Join(t.TempDir(), "logs")
			if !tc.noRoot {
				require.NoError(t, os.MkdirAll(root, 0o755))
			}
			for _, b := range tc.builds {
				dir := filepath.Join(root, b.name)
				require.NoError(t, os.MkdirAll(dir, 0o755))
				if !b.empty {
					f := filepath.Join(dir, "elastic-agent-20260101.ndjson")
					require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
					setTime(t, f, b.age)
				}
				if b.dirAge != nil {
					setTime(t, dir, *b.dirAge)
				}
			}
			for _, f := range tc.files {
				require.NoError(t, os.WriteFile(filepath.Join(root, f), []byte("x"), 0o600))
			}

			require.NoError(t, CleanupBuildLogs(newTestLog(t), root, current))

			for _, name := range tc.kept {
				assert.DirExists(t, filepath.Join(root, name))
			}
			for _, name := range tc.removed {
				assert.NoDirExists(t, filepath.Join(root, name))
			}
			for _, f := range tc.files {
				assert.FileExists(t, filepath.Join(root, f))
			}
		})
	}
}

func TestCleanupBuildLogsReportsRemovalErrors(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("cannot make a directory undeletable")
	}
	const current = "9.4.0-aaaaaa"
	root := t.TempDir()
	for name, age := range map[string]time.Duration{
		current:        0,
		"9.3.2-eeeeee": time.Hour,
		"9.3.0-bbbbbb": 3 * time.Hour,
		"9.3.1-cccccc": 4 * time.Hour,
	} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		f := filepath.Join(dir, "elastic-agent-20260101.ndjson")
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
		setTime(t, f, age)
	}
	// a directory that cannot be emptied is reported, the other one is still removed
	locked := filepath.Join(root, "9.3.0-bbbbbb")
	require.NoError(t, os.Chmod(locked, 0o555))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	err := CleanupBuildLogs(newTestLog(t), root, current)

	require.Error(t, err)
	assert.ErrorContains(t, err, "9.3.0-bbbbbb")
	assert.NoDirExists(t, filepath.Join(root, "9.3.1-cccccc"))
	assert.DirExists(t, filepath.Join(root, "9.3.2-eeeeee"))
}

func TestLastWrite(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	newest := time.Now().Add(-time.Hour).Truncate(time.Second)
	write := func(rel string, ts time.Time) {
		f := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
		require.NoError(t, os.Chtimes(f, ts, ts))
	}
	write("elastic-agent-1.ndjson", old)
	write(filepath.Join("components", "httpjson", "trace.ndjson"), newest)

	assert.True(t, newest.Equal(lastWrite(dir)), "the newest file below any subdirectory counts")
	assert.True(t, lastWrite(filepath.Join(dir, "missing")).IsZero())
	assert.True(t, lastWrite(t.TempDir()).IsZero(), "an empty directory has no write time")
}

// setTime sets the modification time of a file or a directory to age ago.
func setTime(t *testing.T, path string, age time.Duration) {
	t.Helper()
	ts := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(path, ts, ts))
}

func newTestLog(t *testing.T) *logger.Logger {
	t.Helper()
	l, _ := loggertest.New(t.Name())
	return l
}

// TestCleanupBuildLogsDoesNotFollowLinks checks that a link to something outside of the logs root is never
// followed, wherever it is.
func TestCleanupBuildLogsDoesNotFollowLinks(t *testing.T) {
	const current = "9.4.0-aaaaaa"

	tests := []struct {
		name string
		// builds are the build log directories, with how long ago their file was written
		builds map[string]time.Duration
		// links are links to the outside directory, by path in the logs root
		links []string
		// outsideAge is how long ago the file in the outside directory was written, now if not set
		outsideAge time.Duration
		// rootIsLink makes the logs root a link to the directory that holds the builds
		rootIsLink bool
		wantErr    bool
		// kept and removed are the paths in the logs root that must and must not exist after the cleanup, a link
		// counts as existing even if it is the one to a directory
		kept    []string
		removed []string
	}{
		{
			name:    "a link in place of a build directory is ignored",
			builds:  map[string]time.Duration{current: 0, "9.3.0-bbbbbb": 2 * time.Hour, "9.3.1-cccccc": time.Hour},
			links:   []string{"9.2.0-dddddd"},
			kept:    []string{current, "9.3.1-cccccc", "9.2.0-dddddd"},
			removed: []string{"9.3.0-bbbbbb"},
		},
		{
			name:    "a link inside a removed build directory is removed, not followed",
			builds:  map[string]time.Duration{current: 0, "9.3.0-bbbbbb": 2 * time.Hour, "9.3.1-cccccc": time.Hour},
			links:   []string{"9.3.0-bbbbbb/link"},
			kept:    []string{current, "9.3.1-cccccc"},
			removed: []string{"9.3.0-bbbbbb"},
		},
		{
			// the file the link points to was written more recently than any log
			name:    "a link inside a build directory does not make it more recent",
			builds:  map[string]time.Duration{current: 0, "9.3.0-bbbbbb": 3 * time.Hour, "9.3.1-cccccc": 2 * time.Hour},
			links:   []string{"9.3.0-bbbbbb/link"},
			kept:    []string{current, "9.3.1-cccccc"},
			removed: []string{"9.3.0-bbbbbb"},
		},
		{
			name:       "a link in place of the logs root fails the cleanup",
			builds:     map[string]time.Duration{current: 0, "9.3.0-bbbbbb": 2 * time.Hour, "9.3.1-cccccc": time.Hour},
			rootIsLink: true,
			wantErr:    true,
			kept:       []string{current, "9.3.0-bbbbbb", "9.3.1-cccccc"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// outside is a directory that is not part of the logs, its file must survive
			outside := t.TempDir()
			outsideFile := filepath.Join(outside, "keep.txt")
			require.NoError(t, os.WriteFile(outsideFile, []byte("keep"), 0o600))
			setTime(t, outsideFile, tc.outsideAge)

			// the builds are in the logs root, or in the directory its link points to
			root := t.TempDir()
			buildsDir := root
			if tc.rootIsLink {
				buildsDir = t.TempDir()
				root = filepath.Join(t.TempDir(), "logs")
				if err := os.Symlink(buildsDir, root); err != nil {
					t.Skipf("cannot create symbolic links: %s", err)
				}
			}
			for name, age := range tc.builds {
				f := filepath.Join(buildsDir, name, "elastic-agent-20260101.ndjson")
				require.NoError(t, os.MkdirAll(filepath.Dir(f), 0o755))
				require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
				setTime(t, f, age)
			}
			for _, link := range tc.links {
				if err := os.Symlink(outside, filepath.Join(buildsDir, link)); err != nil {
					t.Skipf("cannot create symbolic links: %s", err)
				}
			}

			err := CleanupBuildLogs(newTestLog(t), root, current)

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.FileExists(t, outsideFile, "the cleanup must not reach the outside directory")
			for _, p := range tc.kept {
				_, err := os.Lstat(filepath.Join(root, p))
				assert.NoErrorf(t, err, "%s must be kept", p)
			}
			for _, p := range tc.removed {
				_, err := os.Lstat(filepath.Join(root, p))
				assert.ErrorIsf(t, err, fs.ErrNotExist, "%s must be removed", p)
			}
		})
	}
}

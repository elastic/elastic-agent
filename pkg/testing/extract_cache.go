// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ExtractCacheEnvVar disables the per-process extraction cache when set to
// "false" (or any value strconv.ParseBool reads as false). Every Fixture then
// extracts its archive into its own work directory, as it did before the cache
// existed.
const ExtractCacheEnvVar = "AGENT_TEST_EXTRACT_CACHE"

// extractCacheHardlinkMinSize is the size from which a regular file in the
// cached tree is hard-linked into a fixture's work directory instead of copied.
//
// The agent package is ~450 entries and ~1.3 GB, of which 17 files (the agent
// and component binaries) hold 99.7% of the bytes. Hard-linking those makes
// populating a work directory a matter of milliseconds, while every small file
// (configuration, spec files, hash and version files) is a private copy, so
// writes to them never leak between fixtures. See the documentation on
// extractCache for the rules this relies on.
const extractCacheHardlinkMinSize = 1 << 20

// extractCache extracts each distinct archive once per test process and
// populates fixture work directories from that tree.
//
// Extracting the agent package costs 5-8 s per fixture in CI (inflate bound),
// and a test job prepares 15-50 fixtures, so the extraction alone was 10-20% of
// the job. With the cache the archive is inflated once and each fixture gets
// its tree in well under a second.
//
// Large regular files are hard-linked, so they share an inode with the cached
// tree and with every other fixture of the same archive. That is safe as long
// as nothing writes to them in place, which holds for the test framework and
// the tests: the fixture writes elastic-agent.yml, otel.yml and other small
// files (private copies), removes spec files (unlink only affects this tree),
// and prepareComponents removes a destination before copying a binary over it;
// the agent itself only writes new files under data/ when run from the work
// directory, and `elastic-agent install` copies the tree instead of modifying
// it. Directories and symlinks are always recreated. A helper that needs to
// modify a binary in place must remove it first or write a new file and rename
// it over the old one.
type extractCache struct {
	mu      sync.Mutex
	root    string
	entries map[string]*extractCacheEntry
}

type extractCacheEntry struct {
	once sync.Once
	dir  string
	err  error
}

var sharedExtractCache = &extractCache{}

// extractCacheEnabled reports whether the extraction cache is in use.
func extractCacheEnabled() bool {
	v, ok := os.LookupEnv(ExtractCacheEnvVar)
	if !ok {
		return true
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		return true
	}
	return enabled
}

// extractArtifactCached is ExtractArtifact with the per-process cache in front
// of it for .tar.gz and .zip archives. On any cache failure it falls back to a
// direct extraction, so a cache problem can only cost time, never a test.
func extractArtifactCached(l Logger, artifactFile, outputDir string) error {
	_, ext, err := splitFileType(filepath.Base(artifactFile))
	if err != nil {
		return err
	}
	if !extractCacheEnabled() || (ext != ".tar.gz" && ext != ".zip") {
		return ExtractArtifact(l, artifactFile, outputDir)
	}

	cacheDir, err := sharedExtractCache.extracted(l, artifactFile)
	if err != nil {
		l.Logf("Extraction cache unavailable for %s, extracting directly: %s", filepath.Base(artifactFile), err)
		return ExtractArtifact(l, artifactFile, outputDir)
	}
	l.Logf("Populating %s from cached extraction of %s", outputDir, filepath.Base(artifactFile))
	if err := populateFromExtractCache(cacheDir, outputDir); err != nil {
		l.Logf("Failed to populate %s from the extraction cache, extracting directly: %s", outputDir, err)
		if rmErr := os.RemoveAll(outputDir); rmErr != nil {
			return fmt.Errorf("populating from cache failed (%w) and removing the partial output failed: %w", err, rmErr)
		}
		if mkErr := os.MkdirAll(outputDir, 0o755); mkErr != nil {
			return fmt.Errorf("populating from cache failed (%w) and recreating the output directory failed: %w", err, mkErr)
		}
		return ExtractArtifact(l, artifactFile, outputDir)
	}
	l.Logf("Completed populating %s from cached extraction of %s", outputDir, filepath.Base(artifactFile))
	return nil
}

// extracted returns the directory holding the extracted content of
// artifactFile, extracting it on first use.
func (c *extractCache) extracted(l Logger, artifactFile string) (string, error) {
	key, err := extractCacheKey(artifactFile)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	if c.root == "" {
		// One cache per process: an archive with the same path, size and
		// modification time is the same archive, but a tree populated by a
		// previous process may have been modified by a test, so it is never
		// reused. Stale caches of this user are removed at process exit by
		// RemoveExtractCache, which the integration test packages call from
		// TestMain.
		c.root = filepath.Join(os.TempDir(), fmt.Sprintf("elastic-agent-test-extract-%d", os.Getpid()))
	}
	if c.entries == nil {
		c.entries = make(map[string]*extractCacheEntry)
	}
	entry, ok := c.entries[key]
	if !ok {
		entry = &extractCacheEntry{dir: filepath.Join(c.root, key)}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		// Extract into a temporary directory and rename it into place, so a
		// failed or interrupted extraction never looks like a complete one.
		if err := os.MkdirAll(c.root, 0o755); err != nil {
			entry.err = fmt.Errorf("creating extraction cache root %s: %w", c.root, err)
			return
		}
		tmp := entry.dir + ".tmp"
		if err := os.RemoveAll(tmp); err != nil {
			entry.err = fmt.Errorf("cleaning %s: %w", tmp, err)
			return
		}
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			entry.err = fmt.Errorf("creating %s: %w", tmp, err)
			return
		}
		if err := ExtractArtifact(l, artifactFile, tmp); err != nil {
			_ = os.RemoveAll(tmp)
			entry.err = err
			return
		}
		if err := os.Rename(tmp, entry.dir); err != nil {
			_ = os.RemoveAll(tmp)
			entry.err = fmt.Errorf("moving %s into the extraction cache: %w", tmp, err)
			return
		}
	})
	return entry.dir, entry.err
}

// extractCacheKey identifies an archive by its absolute path, size and
// modification time.
func extractCacheKey(artifactFile string) (string, error) {
	abs, err := filepath.Abs(artifactFile)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", abs, info.Size(), info.ModTime().UnixNano())))
	return hex.EncodeToString(sum[:8]), nil
}

// populateFromExtractCache recreates the tree under cacheDir in outputDir:
// directories and symlinks are recreated, regular files of at least
// extractCacheHardlinkMinSize are hard-linked (copied if the link fails, for
// example across file systems) and smaller files are copied. Both trees are
// accessed through an os.Root so no entry can escape either directory.
func populateFromExtractCache(cacheDir, outputDir string) error {
	src, err := os.OpenRoot(cacheDir)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenRoot(outputDir)
	if err != nil {
		return err
	}
	defer dst.Close()

	return fs.WalkDir(src.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.FromSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			return dst.MkdirAll(rel, mode.Perm())
		case mode&fs.ModeSymlink != 0:
			target, err := src.Readlink(rel)
			if err != nil {
				return err
			}
			return dst.Symlink(target, rel)
		case mode.IsRegular():
			if info.Size() >= extractCacheHardlinkMinSize {
				// os.Root cannot link across two roots. Both paths are the
				// root directories joined with an entry name that was walked
				// in one of them, so they cannot escape.
				if err := os.Link(filepath.Join(cacheDir, rel), filepath.Join(outputDir, rel)); err == nil {
					return nil
				}
			}
			return copyFileWithMode(src, dst, rel, mode.Perm())
		default:
			// untar and unzip skip everything else as well
			return nil
		}
	})
}

func copyFileWithMode(src, dst *os.Root, rel string, perm fs.FileMode) (err error) {
	in, err := src.Open(rel)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := dst.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = io.Copy(out, in)
	return err
}

// RemoveExtractCache deletes this process's extraction cache and the caches
// left behind by earlier test processes of the same user. It is meant to be
// called from TestMain after the tests have run; it is a no-op when the cache
// was never used.
func RemoveExtractCache() error {
	c := sharedExtractCache
	c.mu.Lock()
	root := c.root
	c.mu.Unlock()

	var errs []error
	if root != "" {
		if err := os.RemoveAll(root); err != nil {
			errs = append(errs, err)
		}
	}
	// Caches of processes that are no longer running (a test binary that was
	// killed never reaches this point). Removing a directory that another live
	// test process is using would break its fixtures, so only directories of
	// dead processes are removed.
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "elastic-agent-test-extract-*"))
	for _, dir := range matches {
		if dir == root {
			continue
		}
		pidStr := strings.TrimPrefix(filepath.Base(dir), "elastic-agent-test-extract-")
		pidStr = strings.TrimSuffix(pidStr, ".tmp")
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid == os.Getpid() || processAlive(pid) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testArchiveEntry struct {
	name    string
	mode    os.FileMode
	content []byte
	link    string // symlink target, when set the entry is a symlink
	dir     bool
}

func testArchiveEntries() []testArchiveEntry {
	big := bytes.Repeat([]byte("binary-"), (extractCacheHardlinkMinSize/7)+1)
	return []testArchiveEntry{
		{name: "elastic-agent-9.9.9/", dir: true, mode: 0o755},
		{name: "elastic-agent-9.9.9/elastic-agent.yml", mode: 0o600, content: []byte("agent: config\n")},
		{name: "elastic-agent-9.9.9/.build_hash.txt", mode: 0o644, content: []byte("abcdef")},
		{name: "elastic-agent-9.9.9/data/", dir: true, mode: 0o755},
		{name: "elastic-agent-9.9.9/data/elastic-agent-abcdef/", dir: true, mode: 0o755},
		{name: "elastic-agent-9.9.9/data/elastic-agent-abcdef/elastic-agent", mode: 0o755, content: big},
		{name: "elastic-agent-9.9.9/data/elastic-agent-abcdef/components/", dir: true, mode: 0o755},
		{name: "elastic-agent-9.9.9/data/elastic-agent-abcdef/components/fake.spec.yml", mode: 0o644, content: []byte("spec")},
		{name: "elastic-agent-9.9.9/elastic-agent", link: "data/elastic-agent-abcdef/elastic-agent"},
	}
}

func writeTestTarGz(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, e := range testArchiveEntries() {
		hdr := &tar.Header{Name: e.name, Mode: int64(e.mode), ModTime: time.Now()}
		switch {
		case e.dir:
			hdr.Typeflag = tar.TypeDir
		case e.link != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.link
			hdr.Mode = 0o777
		default:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.content))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if !e.dir && e.link == "" {
			_, err := tw.Write(e.content)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
}

func writeTestZip(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range testArchiveEntries() {
		if e.link != "" {
			continue // the zip extractor does not handle symlinks
		}
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.dir {
			hdr.SetMode(e.mode | os.ModeDir)
		} else {
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		require.NoError(t, err)
		if !e.dir {
			_, err := w.Write(e.content)
			require.NoError(t, err)
		}
	}
	require.NoError(t, zw.Close())
}

func assertExtractedTree(t *testing.T, dir string, withSymlink bool) {
	t.Helper()
	for _, e := range testArchiveEntries() {
		p := filepath.Join(dir, filepath.FromSlash(e.name))
		info, err := os.Lstat(p)
		switch {
		case e.link != "":
			if !withSymlink {
				continue
			}
			require.NoError(t, err, p)
			assert.True(t, info.Mode()&os.ModeSymlink != 0, "%s should be a symlink", p)
			target, err := os.Readlink(p)
			require.NoError(t, err)
			assert.Equal(t, e.link, target)
		case e.dir:
			require.NoError(t, err, p)
			assert.True(t, info.IsDir(), "%s should be a directory", p)
		default:
			require.NoError(t, err, p)
			got, err := os.ReadFile(p)
			require.NoError(t, err)
			assert.Equal(t, e.content, got, "content of %s", p)
			if runtime.GOOS != "windows" {
				assert.Equal(t, e.mode, info.Mode().Perm(), "mode of %s", p)
			}
		}
	}
}

func newTestExtractCache(t *testing.T) *extractCache {
	t.Helper()
	c := &extractCache{root: filepath.Join(t.TempDir(), "cache")}
	old := sharedExtractCache
	sharedExtractCache = c
	t.Cleanup(func() { sharedExtractCache = old })
	return c
}

func TestExtractArtifactCached_TarGz(t *testing.T) {
	c := newTestExtractCache(t)
	archive := filepath.Join(t.TempDir(), "elastic-agent-9.9.9-linux-x86_64.tar.gz")
	writeTestTarGz(t, archive)

	out1 := t.TempDir()
	require.NoError(t, extractArtifactCached(t, archive, out1))
	assertExtractedTree(t, out1, true)

	out2 := t.TempDir()
	require.NoError(t, extractArtifactCached(t, archive, out2))
	assertExtractedTree(t, out2, true)

	// the archive was extracted exactly once, into the cache
	entries, err := os.ReadDir(c.root)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	cached := filepath.Join(c.root, entries[0].Name())
	assertExtractedTree(t, cached, true)

	bigRel := filepath.FromSlash("elastic-agent-9.9.9/data/elastic-agent-abcdef/elastic-agent")
	smallRel := filepath.FromSlash("elastic-agent-9.9.9/elastic-agent.yml")

	// the large binary is a hardlink shared with the cache, the small file is a private copy
	assert.True(t, sameFile(t, filepath.Join(cached, bigRel), filepath.Join(out1, bigRel)), "large file should be hard-linked")
	assert.True(t, sameFile(t, filepath.Join(out1, bigRel), filepath.Join(out2, bigRel)), "large file should be shared between fixtures")
	assert.False(t, sameFile(t, filepath.Join(cached, smallRel), filepath.Join(out1, smallRel)), "small file should be copied")

	// writing a small file in place in one tree does not affect the others
	require.NoError(t, os.WriteFile(filepath.Join(out1, smallRel), []byte("changed"), 0o600))
	got, err := os.ReadFile(filepath.Join(out2, smallRel))
	require.NoError(t, err)
	assert.Equal(t, "agent: config\n", string(got))
	got, err = os.ReadFile(filepath.Join(cached, smallRel))
	require.NoError(t, err)
	assert.Equal(t, "agent: config\n", string(got))

	// removing a hard-linked file from one tree leaves the others intact
	require.NoError(t, os.Remove(filepath.Join(out1, bigRel)))
	_, err = os.Stat(filepath.Join(out2, bigRel))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(cached, bigRel))
	require.NoError(t, err)

	// cleanup removes the cache
	require.NoError(t, RemoveExtractCache())
	_, err = os.Stat(c.root)
	assert.True(t, os.IsNotExist(err), "cache root should be gone")
}

func TestExtractArtifactCached_Zip(t *testing.T) {
	newTestExtractCache(t)
	archive := filepath.Join(t.TempDir(), "elastic-agent-9.9.9-windows-x86_64.zip")
	writeTestZip(t, archive)

	out1 := t.TempDir()
	require.NoError(t, extractArtifactCached(t, archive, out1))
	assertExtractedTree(t, out1, false)
	out2 := t.TempDir()
	require.NoError(t, extractArtifactCached(t, archive, out2))
	assertExtractedTree(t, out2, false)
}

func TestExtractArtifactCached_Disabled(t *testing.T) {
	c := newTestExtractCache(t)
	t.Setenv(ExtractCacheEnvVar, "false")
	archive := filepath.Join(t.TempDir(), "elastic-agent-9.9.9-linux-x86_64.tar.gz")
	writeTestTarGz(t, archive)

	out := t.TempDir()
	require.NoError(t, extractArtifactCached(t, archive, out))
	assertExtractedTree(t, out, true)
	_, err := os.Stat(c.root)
	assert.True(t, os.IsNotExist(err), "cache must not be created when disabled")
}

func TestExtractArtifactCached_DifferentArchivesDoNotCollide(t *testing.T) {
	c := newTestExtractCache(t)
	dir := t.TempDir()
	a := filepath.Join(dir, "a", "elastic-agent-9.9.9-linux-x86_64.tar.gz")
	b := filepath.Join(dir, "b", "elastic-agent-9.9.9-linux-x86_64.tar.gz")
	require.NoError(t, os.MkdirAll(filepath.Dir(a), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(b), 0o755))
	writeTestTarGz(t, a)
	writeTestTarGz(t, b)

	require.NoError(t, extractArtifactCached(t, a, t.TempDir()))
	require.NoError(t, extractArtifactCached(t, b, t.TempDir()))
	entries, err := os.ReadDir(c.root)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "archives at different paths get their own cache entries")
}

// TestUnzipParallelMatchesSequential checks that the parallel zip extraction
// produces the same tree as the archive describes.
func TestUnzipExtractsTree(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "elastic-agent-9.9.9-windows-x86_64.zip")
	writeTestZip(t, archive)
	out := t.TempDir()
	require.NoError(t, unzip(archive, out))
	assertExtractedTree(t, out, false)
}

func TestUntarExtractsTree(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "elastic-agent-9.9.9-linux-x86_64.tar.gz")
	writeTestTarGz(t, archive)
	out := t.TempDir()
	require.NoError(t, untar(archive, out))
	assertExtractedTree(t, out, true)
}

// TestExtractRealArchiveTiming times the extraction paths on a real agent
// package. It only runs when AGENT_TEST_ARCHIVE points at a .tar.gz or .zip
// package, for example:
//
//	AGENT_TEST_ARCHIVE=/tmp/elastic-agent-9.7.0-SNAPSHOT-linux-x86_64.tar.gz go test ./pkg/testing -run TestExtractRealArchiveTiming -v
func TestExtractRealArchiveTiming(t *testing.T) {
	archive := os.Getenv("AGENT_TEST_ARCHIVE")
	if archive == "" {
		t.Skip("AGENT_TEST_ARCHIVE not set")
	}
	newTestExtractCache(t)
	t.Cleanup(func() { _ = RemoveExtractCache() })

	start := time.Now()
	require.NoError(t, ExtractArtifact(t, archive, t.TempDir()))
	t.Logf("direct extraction: %s", time.Since(start).Round(time.Millisecond))

	start = time.Now()
	require.NoError(t, extractArtifactCached(t, archive, t.TempDir()))
	t.Logf("first cached extraction (extract + populate): %s", time.Since(start).Round(time.Millisecond))

	start = time.Now()
	require.NoError(t, extractArtifactCached(t, archive, t.TempDir()))
	t.Logf("second cached extraction (populate only): %s", time.Since(start).Round(time.Millisecond))
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	ia, err := os.Stat(a)
	require.NoError(t, err)
	ib, err := os.Stat(b)
	require.NoError(t, err)
	return os.SameFile(ia, ib)
}

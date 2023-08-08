// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/pprof/profile"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/version"
)

func TestZipLogs(t *testing.T) {
	// Setup a directory structure of: logs/httpjson/log.ndjson
	{
		paths.SetTop(t.TempDir())
		dir := filepath.Join(paths.Home(), "logs/sub-dir")
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "log.ndjson"), []byte(".\n"), 0o600))
	}

	// Zip the logs directory.
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	require.NoError(t, zipLogs(w, time.Now()))
	require.NoError(t, w.Close())

	type zippedItem struct {
		Name  string
		IsDir bool
	}

	// Read back the contents.
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	var observed []zippedItem
	for _, f := range r.File {
		observed = append(observed, zippedItem{Name: f.Name, IsDir: f.FileInfo().IsDir()})
	}

	// Verify the results.
	expected := []zippedItem{
		{"logs/", true},
		{"logs/elastic-agent-unknow/", true},
		{"logs/elastic-agent-unknow/sub-dir/", true},
		{"logs/elastic-agent-unknow/sub-dir/log.ndjson", false},
	}
	assert.Equal(t, expected, observed)
}

func TestGlobalHooks(t *testing.T) {
	testPkgVer := "1.2.3-test"
	setupPkgVersion(t, testPkgVer, 0o644)
	hooks := GlobalHooks()
	assert.NotEmpty(t, hooks, "multiple hooks should be returned")
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(func() { cancel() })
	for _, h := range hooks {
		output := h.Hook(ctx)
		assert.NotEmpty(t, h, "hook should produce output")
		var ok bool
		var err error
		switch h.Name {
		case "version":
			ok, err = isVersion(output)
			assert.Truef(t, ok, "hook %q returned incompatible data: %q", h.Name, hex.EncodeToString(output))
			assert.NoErrorf(t, err, "hook %q validation error: %v", err)
		case "package version":
			assert.Equal(t, testPkgVer, string(output), "hook package version does not match")
		default:
			ok, err = isPprof(output)
			assert.Truef(t, ok, "hook %q returned incompatible data: %q", h.Name, hex.EncodeToString(output))
			assert.NoErrorf(t, err, "hook %q validation error: %v", err)
		}
	}
}

func TestPackageVersionHook(t *testing.T) {
	for _, h := range GlobalHooks() {
		if h.Name == "package version" {
			testPackageVersionHook(t, h)
			return
		}
	}
	t.Fatal("package version hook not returned by GlobalHooks()")
}

func testPackageVersionHook(t *testing.T, pkgVersHook Hook) {
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	t.Run("package version hook returns an error if no package version file is found", func(t *testing.T) {
		output := pkgVersHook.Hook(ctx)
		assert.True(t, strings.HasPrefix(string(output), "error: "))
	})
	t.Run("package version hook returns an error if package version file is not readable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("windows does not support non-readable permissions on files")
		}
		testPkgVer := "1.2.3-test"
		setupPkgVersion(t, testPkgVer, 0o222)
		output := pkgVersHook.Hook(ctx)
		assert.True(t, strings.HasPrefix(string(output), "error: "))
		assert.True(t, strings.HasSuffix(string(output), "permission denied\""))
	})
	t.Run("package version hook returns all the bytes in file including spaces", func(t *testing.T) {
		testPkgVer := "\r\n   1.2.3-test  \n\t"
		setupPkgVersion(t, testPkgVer, 0o444)
		output := pkgVersHook.Hook(ctx)
		assert.Equal(t, testPkgVer, string(output))
	})
}

func setupPkgVersion(t *testing.T, pkgVer string, fileMode os.FileMode) {
	// setup a fake package version to test the package version hook
	pkgVersPath, err := version.GetAgentPackageVersionFilePath()
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(pkgVersPath) })
	err = os.WriteFile(pkgVersPath, []byte(pkgVer), fileMode)
	require.NoError(t, err)
}

func isVersion(input []byte) (bool, error) {
	return strings.Contains(string(input), "version:"), nil
}

func isPprof(input []byte) (bool, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(input))
	if err != nil {
		return false, err
	}
	uncompressed, err := io.ReadAll(gz)
	if err != nil {
		return false, err
	}
	_, err = profile.ParseUncompressed(uncompressed)
	if err != nil {
		return false, err
	}
	return true, nil
}

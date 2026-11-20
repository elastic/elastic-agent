// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const localManifestFixture = `{
  "version": "9.7.0-SNAPSHOT",
  "build_id": "9.7.0-SNAPSHOT-7f1b17b0eb57",
  "branch": "main",
  "projects": {
    "fleet-server": {
      "branch": "main",
      "commit_hash": "deadbeef",
      "packages": {
        "fleet-server-9.7.0-SNAPSHOT-linux-x86_64.tar.gz": {
          "url": "https://artifacts-snapshot.elastic.co/fleet-server/pkg.tar.gz"
        }
      }
    }
  }
}`

// TestDownloadManifestFromLocalFile covers the local packaging flow: a merged
// manifest written by `mage dra:mergeManifests` is handed to packaging as a
// path instead of a published URL.
func TestDownloadManifestFromLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-artifacts-merged.json")
	require.NoError(t, os.WriteFile(path, []byte(localManifestFixture), 0o600))

	for name, location := range map[string]string{
		"path":      path,
		"file URL":  "file://" + path,
		"rel. path": relativeTo(t, path),
	} {
		t.Run(name, func(t *testing.T) {
			build, err := DownloadManifest(context.Background(), location)
			require.NoError(t, err)
			assert.Equal(t, "9.7.0-SNAPSHOT", build.Version)
			assert.Equal(t, "9.7.0-SNAPSHOT-7f1b17b0eb57", build.BuildID)
			require.Contains(t, build.Projects, "fleet-server")
			assert.Contains(t, build.Projects["fleet-server"].Packages, "fleet-server-9.7.0-SNAPSHOT-linux-x86_64.tar.gz")
		})
	}
}

func TestDownloadManifestFromMissingLocalFile(t *testing.T) {
	_, err := DownloadManifest(context.Background(), filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading local manifest")
}

func TestDownloadManifestStillRejectsDisallowedHosts(t *testing.T) {
	// Reading a local file must not have turned into "anything goes".
	_, err := DownloadManifest(context.Background(), "https://example.invalid/manifest.json")
	assert.ErrorIs(t, err, errorNotAllowedManifestURL)
}

func TestDownloadPackageStillRejectsDisallowedHosts(t *testing.T) {
	// A local manifest is only a list of URLs; the packages it names are still
	// checked against the allow list when they are fetched.
	err := DownloadPackage(context.Background(), "https://example.invalid/pkg.tar.gz", filepath.Join(t.TempDir(), "pkg.tar.gz"))
	assert.ErrorIs(t, err, errorNotAllowedManifestURL)
}

func relativeTo(t *testing.T, path string) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	rel, err := filepath.Rel(cwd, path)
	require.NoError(t, err)
	return rel
}

func TestLocalManifestPath(t *testing.T) {
	for name, tc := range map[string]struct {
		location  string
		wantPath  string
		wantLocal bool
	}{
		"absolute path":   {location: "/tmp/merged.json", wantPath: "/tmp/merged.json", wantLocal: true},
		"relative path":   {location: "build/dra/merged.json", wantPath: "build/dra/merged.json", wantLocal: true},
		"file URL":        {location: "file:///tmp/merged.json", wantPath: "/tmp/merged.json", wantLocal: true},
		"windows path":    {location: `C:\build\dra\merged.json`, wantPath: `C:\build\dra\merged.json`, wantLocal: true},
		"https URL":       {location: "https://artifacts-snapshot.elastic.co/m.json", wantLocal: false},
		"http URL":        {location: "http://artifacts-snapshot.elastic.co/m.json", wantLocal: false},
		"gs URL":          {location: "gs://bucket/m.json", wantLocal: false},
		"schemeless host": {location: "//artifacts-snapshot.elastic.co/m.json", wantPath: "//artifacts-snapshot.elastic.co/m.json", wantLocal: true},
	} {
		t.Run(name, func(t *testing.T) {
			path, local := localManifestPath(tc.location)
			assert.Equal(t, tc.wantLocal, local)
			if tc.wantLocal {
				assert.Equal(t, tc.wantPath, path)
			}
		})
	}
}

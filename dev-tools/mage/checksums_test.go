// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentDestination(t *testing.T) {
	dropPath := filepath.Join("drop", "linux-x86_64.tar.gz")
	tests := []struct {
		name   string
		dest   string
		expect string
	}{{
		name:   "top-level NOTICE.txt",
		dest:   filepath.Join(dropPath, "NOTICE.txt"),
		expect: filepath.Join(dropPath, "NOTICE.apm-server.txt"),
	}, {
		name:   "top-level LICENSE.txt",
		dest:   filepath.Join(dropPath, "LICENSE.txt"),
		expect: filepath.Join(dropPath, "LICENSE.apm-server.txt"),
	}, {
		name:   "top-level .build_hash.txt",
		dest:   filepath.Join(dropPath, ".build_hash.txt"),
		expect: filepath.Join(dropPath, ".build_hash.apm-server.txt"),
	}, {
		name:   "nested NOTICE.txt",
		dest:   filepath.Join(dropPath, "kibana", "NOTICE.txt"),
		expect: filepath.Join(dropPath, "kibana", "NOTICE.apm-server.txt"),
	}, {
		name:   "other top-level file is not renamed",
		dest:   filepath.Join(dropPath, "apm-server.yml"),
		expect: filepath.Join(dropPath, "apm-server.yml"),
	}, {
		name:   "drop path itself is not renamed",
		dest:   dropPath,
		expect: dropPath,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, componentDestination(tc.dest, "apm-server"))
		})
	}
}

func TestComponentCopyOptions_RenamesMetadataFiles(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, filepath.Join(root, "comp-a"), map[string]string{
		"NOTICE.txt":        "notice a",
		"LICENSE.txt":       "license a",
		".build_hash.txt":   "hash a",
		"kibana/NOTICE.txt": "nested notice a",
		"comp-a":            "binary a",
		"shared/only-a.yml": "a",
	})
	writeFiles(t, filepath.Join(root, "comp-b"), map[string]string{
		"NOTICE.txt":        "notice b",
		"LICENSE.txt":       "license b",
		"kibana/NOTICE.txt": "nested notice b",
		"comp-b":            "binary b",
		"shared/only-b.yml": "b",
	})
	expected := map[string]string{
		"NOTICE.comp-a.txt":        "notice a",
		"LICENSE.comp-a.txt":       "license a",
		".build_hash.comp-a.txt":   "hash a",
		"kibana/NOTICE.comp-a.txt": "nested notice a",
		"comp-a":                   "binary a",
		"shared/only-a.yml":        "a",
		"NOTICE.comp-b.txt":        "notice b",
		"LICENSE.comp-b.txt":       "license b",
		"kibana/NOTICE.comp-b.txt": "nested notice b",
		"comp-b":                   "binary b",
		"shared/only-b.yml":        "b",
	}

	// the result must not depend on the order the components are copied in
	for _, order := range [][]string{{"comp-a", "comp-b"}, {"comp-b", "comp-a"}} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			dropPath := filepath.Join(t.TempDir(), "drop")
			for _, comp := range order {
				require.NoError(t, copy.Copy(filepath.Join(root, comp), dropPath, componentCopyOptions(comp)))
			}

			assert.Equal(t, expected, readFiles(t, dropPath))
		})
	}
}

func TestComponentCopyOptions_FailsOnOverwrite(t *testing.T) {
	tests := []struct {
		name     string
		compA    map[string]string
		compB    map[string]string
		conflict string
	}{{
		name:     "same file in both components",
		compA:    map[string]string{"shared/clash.yml": "a", "shared/only-a.yml": "a"},
		compB:    map[string]string{"shared/clash.yml": "b"},
		conflict: filepath.Join("shared", "clash.yml"),
	}, {
		// the renamed destination is checked, not the original name
		name:     "renamed metadata file",
		compA:    map[string]string{"NOTICE.comp-b.txt": "comp-a ships a file named after comp-b", "NOTICE.comp-a.txt": "a"},
		compB:    map[string]string{"NOTICE.txt": "notice b"},
		conflict: "NOTICE.comp-b.txt",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFiles(t, filepath.Join(root, "comp-a"), tc.compA)
			writeFiles(t, filepath.Join(root, "comp-b"), tc.compB)
			dropPath := filepath.Join(root, "drop")

			require.NoError(t, copy.Copy(filepath.Join(root, "comp-a"), dropPath, componentCopyOptions("comp-a")))
			err := copy.Copy(filepath.Join(root, "comp-b"), dropPath, componentCopyOptions("comp-b"))
			require.ErrorContains(t, err, "component comp-b overwrites existing file "+filepath.Join(dropPath, tc.conflict))
		})
	}
}

func TestComponentCopyOptions_FailsOnFileLeftInDropPath(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, filepath.Join(root, "comp-a"), map[string]string{"NOTICE.txt": "notice a"})
	// the drop path is not cleaned between builds, e.g. with KEEP_ARCHIVE
	dropPath := filepath.Join(root, "drop")
	writeFiles(t, dropPath, map[string]string{"NOTICE.comp-a.txt": "left from a previous build"})

	err := copy.Copy(filepath.Join(root, "comp-a"), dropPath, componentCopyOptions("comp-a"))
	require.ErrorContains(t, err, "component comp-a overwrites existing file "+filepath.Join(dropPath, "NOTICE.comp-a.txt"))
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

// readFiles returns the content of all files under dir, keyed by their slash-separated relative path.
func readFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	fsys := os.DirFS(dir)
	require.NoError(t, fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		files[path] = string(content)
		return nil
	}))
	return files
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentCopyOptions_WarnsOnOverwrite(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	root := t.TempDir()
	writeFiles(t, filepath.Join(root, "comp-a"), map[string]string{
		"NOTICE.txt":            "notice a",
		"comp-a":                "binary a",
		"shared/only-a.yml":     "a",
		"NOTICE.comp-a.txt":     "unique notice a",
		"nested/same/clash.txt": "nested a",
	})
	writeFiles(t, filepath.Join(root, "comp-b"), map[string]string{
		"NOTICE.txt":            "notice b",
		"comp-b":                "binary b",
		"shared/only-b.yml":     "b",
		"nested/same/clash.txt": "nested b",
	})

	dropPath := filepath.Join(root, "drop")
	owners := make(map[string]string)
	for _, comp := range []string{"comp-a", "comp-b"} {
		require.NoError(t, copy.Copy(filepath.Join(root, comp), dropPath, componentCopyOptions(comp, owners)))
	}

	warnings := warningLines(logs.String())
	assert.Len(t, warnings, 2, "expected one warning per overwritten file, got: %v", warnings)
	assert.Contains(t, logs.String(),
		"WARNING: component comp-b overwrites "+filepath.Join(dropPath, "NOTICE.txt")+" previously copied from component comp-a")
	assert.Contains(t, logs.String(),
		"WARNING: component comp-b overwrites "+filepath.Join(dropPath, "nested", "same", "clash.txt")+" previously copied from component comp-a")

	// the last copied component wins, which is the behaviour the warning reports
	content, err := os.ReadFile(filepath.Join(dropPath, "NOTICE.txt"))
	require.NoError(t, err)
	assert.Equal(t, "notice b", string(content))

	// files from merged directories are all kept
	assert.FileExists(t, filepath.Join(dropPath, "shared", "only-a.yml"))
	assert.FileExists(t, filepath.Join(dropPath, "shared", "only-b.yml"))
}

func TestComponentCopyOptions_NoWarningForSameComponent(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	root := t.TempDir()
	writeFiles(t, filepath.Join(root, "comp-a"), map[string]string{"NOTICE.txt": "notice a"})

	dropPath := filepath.Join(root, "drop")
	owners := make(map[string]string)
	for range 2 {
		require.NoError(t, copy.Copy(filepath.Join(root, "comp-a"), dropPath, componentCopyOptions("comp-a", owners)))
	}

	assert.Empty(t, warningLines(logs.String()))
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

func warningLines(logs string) []string {
	var lines []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "WARNING: component") {
			lines = append(lines, line)
		}
	}
	return lines
}

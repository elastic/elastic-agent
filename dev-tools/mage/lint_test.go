// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_tagSetsNeeded(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	untagged := write("plain.go", "package foo\n")
	integrationTagged := write("integration_test.go", "//go:build integration\n\npackage foo\n")
	requirefipsTagged := write("fips.go", "//go:build requirefips\n\npackage foo\n")
	localOnly := write("define_local.go", "//go:build local && !define\n\npackage foo\n")
	defineOnly := write("define_define.go", "//go:build define\n\npackage foo\n")
	neitherTagged := write("define_all.go", "//go:build !define && !local\n\npackage foo\n")
	windowsTagged := write("thing_windows.go", "//go:build windows\n\npackage foo\n")
	deleted := filepath.Join(dir, "does-not-exist.go")

	tests := []struct {
		name    string
		changed []string
		want    []string
	}{
		{
			name:    "no changes",
			changed: nil,
			want:    []string{buildTagSets[0]},
		},
		{
			name:    "unrelated non-go file",
			changed: []string{"docs/architecture.md"},
			want:    []string{buildTagSets[0]},
		},
		{
			name:    "plain go file",
			changed: []string{untagged},
			want:    []string{buildTagSets[0]},
		},
		{
			name:    "deleted file",
			changed: []string{deleted},
			want:    []string{buildTagSets[0]},
		},
		{
			name:    "windows-tagged file doesn't need extra tag sets",
			changed: []string{windowsTagged},
			want:    []string{buildTagSets[0]},
		},
		{
			name:    "integration-tagged file needs both local and define runs",
			changed: []string{integrationTagged},
			want:    []string{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "requirefips-tagged file needs both local and define runs",
			changed: []string{requirefipsTagged},
			want:    []string{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "define-only file needs only the define run",
			changed: []string{defineOnly},
			want:    []string{buildTagSets[0], buildTagSets[2]},
		},
		{
			name:    "local-with-negated-define file needs both (safe over-trigger)",
			changed: []string{localOnly},
			want:    []string{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			// define_all.go's "!define && !local" line matches both words
			// under the simple word-boundary check, which doesn't understand
			// negation. That's a safe over-trigger (see tagSetsNeeded docs),
			// not a bug: it costs an unnecessary run rather than skipping a
			// necessary one.
			name:    "file needing neither tag over-triggers both (safe)",
			changed: []string{neitherTagged},
			want:    []string{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "go.mod changing needs both",
			changed: []string{"go.mod"},
			want:    []string{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tagSetsNeeded(tt.changed))
		})
	}
}

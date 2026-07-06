// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"encoding/json"
	"io"
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
	integrationNotLocal := write("integration_not_local.go", "//go:build integration && !local\n\npackage foo\n")
	localOnly := write("define_local.go", "//go:build local && !define\n\npackage foo\n")
	defineOnly := write("define_define.go", "//go:build define\n\npackage foo\n")
	neitherTagged := write("define_all.go", "//go:build !define && !local\n\npackage foo\n")
	windowsTagged := write("thing_windows.go", "//go:build windows\n\npackage foo\n")
	deleted := filepath.Join(dir, "does-not-exist.go")

	tests := []struct {
		name    string
		changed []string
		want    []buildTagSet
	}{
		{
			name:    "no changes",
			changed: nil,
			want:    []buildTagSet{buildTagSets[0]},
		},
		{
			name:    "unrelated non-go file",
			changed: []string{"docs/architecture.md"},
			want:    []buildTagSet{buildTagSets[0]},
		},
		{
			name:    "plain go file",
			changed: []string{untagged},
			want:    []buildTagSet{buildTagSets[0]},
		},
		{
			name:    "deleted file",
			changed: []string{deleted},
			want:    []buildTagSet{buildTagSets[0]},
		},
		{
			name:    "windows-tagged file doesn't need extra tag sets",
			changed: []string{windowsTagged},
			want:    []buildTagSet{buildTagSets[0]},
		},
		{
			name:    "integration-tagged file needs both local and define runs",
			changed: []string{integrationTagged},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "requirefips-tagged file needs both local and define runs",
			changed: []string{requirefipsTagged},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			// "integration && !local" needs define; over-selecting local is a
			// safe cost, not a bug (see tagSetsNeeded docs).
			name:    "integration-and-not-local file needs define (local over-triggers)",
			changed: []string{integrationNotLocal},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "define-only file needs only the define run",
			changed: []string{defineOnly},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[2]},
		},
		{
			name:    "local-with-negated-define file needs both (safe over-trigger)",
			changed: []string{localOnly},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			// define_all.go's "!define && !local" line matches both words
			// under the simple word-boundary check, which doesn't understand
			// negation. That's a safe over-trigger (see tagSetsNeeded docs),
			// not a bug: it costs an unnecessary run rather than skipping a
			// necessary one.
			name:    "file needing neither tag over-triggers both (safe)",
			changed: []string{neitherTagged},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "go.mod changing needs both",
			changed: []string{"go.mod"},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
		{
			name:    "workflow file changing needs both",
			changed: []string{".github/workflows/golangci-lint.yml"},
			want:    []buildTagSet{buildTagSets[0], buildTagSets[1], buildTagSets[2]},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tagSetsNeeded(tt.changed))
		})
	}
}

func Test_tagSetsNeeded_marshalsToMatrixJSON(t *testing.T) {
	out, err := json.Marshal(tagSetsNeeded([]string{"go.mod"}))
	require.NoError(t, err)
	assert.JSONEq(t,
		`[{"name":"default","tags":""},`+
			`{"name":"local","tags":"integration,requirefips,kubernetes_inner,mage,local"},`+
			`{"name":"define","tags":"integration,requirefips,kubernetes_inner,mage,define"}]`,
		string(out))
}

// With LINT_PLAN_BASE empty (the push / non-PR case), LintPlan prints all tag
// sets and never touches git.
func Test_LintPlan_unsetBasePlansAllSets(t *testing.T) {
	t.Setenv("LINT_PLAN_BASE", "")

	out := captureStdout(t, func() {
		require.NoError(t, LintPlan())
	})

	var got []buildTagSet
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, buildTagSets, got)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	require.NoError(t, w.Close())

	data, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(data)
}

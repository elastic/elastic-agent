// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runner

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCreateRepoZipArchivePreservesMode verifies that file modes — in particular
// the executable bit — survive the repo archiving. A dropped exec bit surfaces
// remotely as "permission denied" when, e.g., a Dockerfile entrypoint script built
// from the copied tree is executed.
func TestCreateRepoZipArchivePreservesMode(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v (%s)", args, err, out)
		}
	}
	git("init")

	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.txt"), []byte("data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")

	dest := filepath.Join(t.TempDir(), "repo.zip")
	if err := createRepoZipArchive(context.Background(), dir, dest); err != nil {
		t.Fatalf("createRepoZipArchive: %v", err)
	}

	zr, err := zip.OpenReader(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	modes := map[string]os.FileMode{}
	for _, f := range zr.File {
		modes[f.Name] = f.Mode()
	}

	if m, ok := modes["run.sh"]; !ok {
		t.Fatal("run.sh missing from archive")
	} else if m&0o111 == 0 {
		t.Errorf("run.sh archive mode = %v, expected executable bits set", m)
	}
	if m, ok := modes["data.txt"]; !ok {
		t.Fatal("data.txt missing from archive")
	} else if m&0o111 != 0 {
		t.Errorf("data.txt archive mode = %v, expected no executable bits", m)
	}
}

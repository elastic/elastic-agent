// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// TempDir creates a temporary directory that will be
// removed if the tests passes. The temporary directory is
// created by joining all elements from path, with the sanitised
// test name.
//
// If path is empty, the temporary directory is created in os.TempDir.
//
// When tests are run with -v, the temporary directory absolute
// path will be logged.
func TempDir(t *testing.T, path ...string) string {
	rootDir := filepath.Join(path...)

	if rootDir == "" {
		rootDir = os.TempDir()
	}

	rootDir, err := filepath.Abs(rootDir)
	if err != nil {
		t.Fatalf("cannot get absolute path: %s", err)
	}

	// Logic copied with small modifications from
	// the Go source code: testing/testing.go
	folderName := t.Name()
	mapper := func(r rune) rune {
		if r < utf8.RuneSelf {
			const allowed = "_-"
			if '0' <= r && r <= '9' ||
				'a' <= r && r <= 'z' ||
				'A' <= r && r <= 'Z' {
				return r
			}
			if strings.ContainsRune(allowed, r) {
				return r
			}
		} else if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return r
		}
		return -1
	}
	folderName = strings.Map(mapper, folderName)

	if err := os.MkdirAll(rootDir, 0o750); err != nil {
		t.Fatalf("error making test dir: %s: %s", rootDir, err)
	}

	tempDir, err := os.MkdirTemp(rootDir, folderName)
	if err != nil {
		t.Fatalf("failed to make temp directory: %s", err)
	}

	cleanup := func() {
		if !t.Failed() {
			if err := os.RemoveAll(tempDir); err != nil {
				// Ungly workaround Windows limitations
				// Windows does not support the Interrup signal, so it might
				// happen that Filebeat is still running, keeping it's registry
				// file open, thus preventing the temporary folder from being
				// removed. So we log the error and move on without failing the
				// test
				if runtime.GOOS == "windows" {
					t.Logf("[WARN] Could not remove temporatry directory '%s': %s", tempDir, err)
				} else {
					t.Errorf("could not remove temp dir '%s': %s", tempDir, err)
				}
			}
		} else {
			t.Logf("Temporary directory saved: %s", tempDir)
		}
	}
	t.Cleanup(cleanup)

	return tempDir
}

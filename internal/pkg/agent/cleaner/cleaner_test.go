// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cleaner

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
)

func TestCleaner(t *testing.T) {
	// Setup
	const watchFileName = "fleet.enc"
	removeFiles := []string{"fleet.yml", "fleet.yml.lock"}

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	dir := t.TempDir()
	watchFilePath := filepath.Join(dir, watchFileName)

	removeFilePaths := make([]string, len(removeFiles))

	checkDir(t, dir, 0)

	// Create files
	err := ioutil.WriteFile(watchFilePath, []byte{}, 0600)
	if err != nil {
		t.Fatal(err)
	}

	for i, fn := range removeFiles {
		removeFilePaths[i] = filepath.Join(dir, fn)
		err := ioutil.WriteFile(removeFilePaths[i], []byte{}, 0600)
		if err != nil {
			t.Fatal(err)
		}
	}

	checkDir(t, dir, len(removeFiles)+1)

	log := logp.NewLogger("dynamic")
	cleaner := New(log, watchFilePath, removeFilePaths, WithCleanWait(500*time.Millisecond))
	err = cleaner.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkDir(t, dir, 1)
}

func checkDir(t *testing.T, dir string, expectedCount int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != expectedCount {
		t.Fatalf("Dir %s expected %d entries, found %d", dir, expectedCount, len(entries))
	}
}

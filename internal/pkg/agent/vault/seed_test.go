// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows
// +build linux windows

package vault

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestGetSeed(t *testing.T) {
	DisableRootCheck()

	dir := t.TempDir()

	fp := filepath.Join(dir, seedFile)

	assert.NoFileExists(t, fp)

	b, err := getSeed(dir)
	assert.NoError(t, err)

	assert.FileExists(t, fp)

	diff := cmp.Diff(int(AES256), len(b))
	if diff != "" {
		t.Error(diff)
	}
}

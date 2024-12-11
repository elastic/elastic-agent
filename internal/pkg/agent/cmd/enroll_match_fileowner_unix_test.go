// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOwnerExecUnix(t *testing.T) {
	path := t.TempDir()
	fp := filepath.Join(path, "testfile")
	fi, err := os.Create(fp)
	require.NoError(t, err)
	defer fi.Close()

	isOwner, err := isOwnerExec(fp)
	require.NoError(t, err)

	require.True(t, isOwner)
}

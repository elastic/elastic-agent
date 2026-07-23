// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && linux

package ess

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func makeTestFS(t *testing.T, size uint64) string {
	t.Helper()

	mountPoint := t.TempDir()
	require.NoError(t, unix.Mount("tmpfs", mountPoint, "tmpfs", 0, fmt.Sprintf("size=%d", size)))
	t.Cleanup(func() {
		require.NoError(t, unix.Unmount(mountPoint, 0))
	})
	return mountPoint
}

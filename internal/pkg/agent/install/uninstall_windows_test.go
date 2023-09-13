// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemovePath(t *testing.T) {
	const binaryName = "testblocking"
	binaryPath, err := filepath.Abs(filepath.Join(binaryName, binaryName+".exe"))
	require.NoErrorf(t, err, "failed abs %s", binaryPath)

	cmd := exec.Command(binaryPath)
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
}

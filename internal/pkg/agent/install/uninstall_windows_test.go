// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const simpleBlockForever = `
package main
func main() {
    select{}
}
`

func TestRemovePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir")
	err := os.Mkdir(dir, 0644)
	require.NoError(t, err)

	src := filepath.Join(dir, "main.go")
	err = os.WriteFile(src, []byte(simpleBlockForever), 0644)
	require.NoError(t, err)

	binary := filepath.Join(dir, "main.exe")
	cmd := exec.Command("go", "build", "-o", binary, src)
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	cmd = exec.Command(binary)
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	err = RemovePath(dir)
	require.NoError(t, err)
}

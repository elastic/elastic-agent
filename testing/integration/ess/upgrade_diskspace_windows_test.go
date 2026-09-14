// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && windows

package ess

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func makeTestFS(t *testing.T, bytes uint64) string {
	t.Helper()

	size := bytes / (1024 * 1024)
	ntfsOverheadMB := uint64(50) + uint64(float64(size)*0.02)
	totalSize := size + ntfsOverheadMB

	tempDir := t.TempDir()
	imagePath := filepath.Join(tempDir, "disk.vhd")

	drive := ""
	for letter := 'F'; letter <= 'Z'; letter++ {
		if _, err := os.Stat(string(letter) + `:\`); os.IsNotExist(err) {
			drive = string(letter)
		}
	}
	if drive == "" {
		t.Fatal("no free drive available for test filesystem")
	}

	runDiskPart(t, t.Context(), tempDir,
		fmt.Sprintf(`create vdisk file="%s" maximum=%d type=expandable`, imagePath, totalSize),
		fmt.Sprintf(`select vdisk file="%s"`, imagePath),
		"attach vdisk",
		"convert mbr",
		"create partition primary",
		"format fs=ntfs quick label=ea-diskspace",
		fmt.Sprintf(`assign letter=%s`, drive),
	)
	t.Cleanup(func() {
		runDiskPart(t, context.WithoutCancel(t.Context()), tempDir,
			fmt.Sprintf(`select vdisk file="%s"`, imagePath),
			"detach vdisk",
		)
	})

	return drive + `:\`
}

func runDiskPart(t *testing.T, ctx context.Context, tempDir string, commands ...string) {
	t.Helper()

	scriptPath := filepath.Join(tempDir, "diskpart.txt")
	require.NoError(t, os.WriteFile(scriptPath, []byte(strings.Join(commands, "\r\n")+"\r\n"), 0o600))

	commandContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	command := exec.CommandContext(commandContext, "diskpart.exe", "/s", scriptPath)
	output, err := command.CombinedOutput()

	require.NoError(t, err, "diskpart failed: %s", output)
	// diskpart exits 0 even when a script command fails so check output for error message
	require.NotContains(t, strings.ToLower(string(output)), "diskpart has encountered an error",
		"diskpart command failed: %s", output)
}

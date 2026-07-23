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

func makeTestFS(t *testing.T, size uint64) string {
	t.Helper()

	tempDir := t.TempDir()
	imagePath := filepath.Join(tempDir, "disk.vhd")
	mountPoint := filepath.Join(tempDir, "mount")
	require.NoError(t, os.Mkdir(mountPoint, 0o755))

	runDiskPart(t, t.Context(), tempDir,
		fmt.Sprintf(`create vdisk file="%s" maximum=%d type=expandable`, imagePath, size/(1024*1024)),
		fmt.Sprintf(`select vdisk file="%s"`, imagePath),
		"attach vdisk",
	)
	t.Cleanup(func() {
		runDiskPart(t, context.WithoutCancel(t.Context()), tempDir,
			fmt.Sprintf(`select vdisk file="%s"`, imagePath),
			"detach vdisk",
		)
	})

	runDiskPart(t, t.Context(), tempDir,
		fmt.Sprintf(`select vdisk file="%s"`, imagePath),
		"convert mbr",
		"create partition primary",
		`format fs=ntfs quick label="elastic-agent-diskspace-test"`,
		fmt.Sprintf(`assign mount="%s%s"`, mountPoint, string(os.PathSeparator)),
	)
	return mountPoint
}

func runDiskPart(t *testing.T, ctx context.Context, tempDir string, commands ...string) {
	t.Helper()

	scriptPath := filepath.Join(tempDir, "diskpart.txt")
	script := strings.Join(commands, "\r\n") + "\r\n"
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o600))
	commandContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	command := exec.CommandContext(commandContext, "diskpart.exe", "/s", scriptPath) //nolint:gosec // G204: test input
	output, err := command.CombinedOutput()
	require.NoError(t, err, "diskpart failed: %s", output)
}

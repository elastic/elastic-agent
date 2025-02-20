// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func TestInstallPath(t *testing.T) {
	tests := map[string]string{
		"single_level": "/opt",
		"multi_level":  "/Library/Agent",
	}

	for name, basePath := range tests {
		t.Run(name, func(t *testing.T) {
			p := paths.InstallPath(basePath)
			require.Equal(t, basePath+"/Elastic/Agent", p)
		})
	}
}

func TestInvalidBasePath(t *testing.T) {
	tests := map[string]struct {
		basePath      string
		expectedError string
	}{
		"relative_path_1": {
			basePath:      "relative/path",
			expectedError: `base path [relative/path] is not absolute`,
		},
		"relative_path_2": {
			basePath:      "./relative/path",
			expectedError: `base path [./relative/path] is not absolute`,
		},
		"empty_path": {
			basePath:      "",
			expectedError: `base path [] is not absolute`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			streams := cli.NewIOStreams()
			cmd := newInstallCommandWithArgs([]string{}, streams)
			err := cmd.Flags().Set(flagInstallBasePath, test.basePath)
			require.NoError(t, err)

			err = installCmd(streams, cmd)

			if test.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.Equal(t, test.expectedError, err.Error())
			}
		})
	}
}

func TestExecUninstall(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("successful uninstall", func(t *testing.T) {
		binPath := filepath.Join(tmpDir, "elastic-agent")
		err := os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0"), 0755)
		require.NoError(t, err)

		var stdout, stderr bytes.Buffer
		streams := &cli.IOStreams{
			Out: &stdout,
			Err: &stderr,
		}

		err = execUninstall(streams, tmpDir, "elastic-agent")
		assert.NoError(t, err)
	})

	t.Run("binary not found", func(t *testing.T) {
		streams := &cli.IOStreams{
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		}

		err := execUninstall(streams, tmpDir, "non-existent-binary")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, fs.ErrNotExist))
	})

	t.Run("directory instead of file", func(t *testing.T) {
		binPath := filepath.Join(tmpDir, "elastic-agent-dir")
		err := os.Mkdir(binPath, 0755)
		require.NoError(t, err)

		streams := &cli.IOStreams{
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		}

		err = execUninstall(streams, tmpDir, "elastic-agent-dir")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected file, found a directory")
	})

	t.Run("command execution failure", func(t *testing.T) {
		binPath := filepath.Join(tmpDir, "failing-agent")
		err := os.WriteFile(binPath, []byte("#!/bin/sh\nexit 1"), 0755)
		require.NoError(t, err)

		streams := &cli.IOStreams{
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		}

		err = execUninstall(streams, tmpDir, "failing-agent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to uninstall elastic-agent")
	})
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
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

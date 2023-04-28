// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallPath(t *testing.T) {
	tests := map[string]string{
		"single_level": "/opt",
		"multi_level":  "/Library/Agent",
	}

	for name, basePath := range tests {
		t.Run(name, func(t *testing.T) {
			p := installPath(basePath)
			require.Equal(t, basePath+"/Elastic/Agent", p)
		})
	}
}

func TestValidateBasePath(t *testing.T) {
	tests := map[string]string{
		"/absolute/path": "",
		"relative/path":  `base path "relative/path" is not absolute`,
	}

	for basePath, expectedError := range tests {
		t.Run(basePath, func(t *testing.T) {
			err := validateBasePath(basePath)

			if expectedError == "" {
				require.NoError(t, err)
			} else {
				require.Equal(t, expectedError, err.Error())
			}
		})
	}
}

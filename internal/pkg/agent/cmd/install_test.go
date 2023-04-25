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

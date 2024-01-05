// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCommand(t *testing.T) {
	tt := []struct {
		Name         string
		ConfigPath   string
		ExpectingErr bool
	}{
		{
			"otel config",
			filepath.Join("testdata", "otel", "otel.yml"),
			false,
		},
		{
			"agent config",
			filepath.Join("testdata", "otel", "elastic-agent.yml"),
			true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateOtelConfig(context.Background(), tc.ConfigPath)
			require.Equal(t, tc.ExpectingErr, err != nil)
		})
	}
}

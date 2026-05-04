// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/edot/otelcol/components"
)

func TestValidateCommand(t *testing.T) {
	tt := []struct {
		Name         string
		ConfigPaths  []string
		ExpectingErr bool
	}{
		{
			"otel config",
			[]string{filepath.Join("testdata", "otel", "otel.yml")},
			false,
		},
		{
			"agent config",
			[]string{filepath.Join("testdata", "otel", "elastic-agent.yml")},
			true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateOtelConfig(context.Background(), tc.ConfigPaths, components.Default())
			require.Equal(t, tc.ExpectingErr, err != nil)
		})
	}
}

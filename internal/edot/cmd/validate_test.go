// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
		ConfigPaths  []string
		ExpectingErr bool
	}{
		{
			"otel config",
			[]string{filepath.Join("testdata", "otel", "otel.yml")},
			false,
		},
		{
			"otel config with set",
			[]string{filepath.Join("testdata", "otel", "otel.yml"), "yaml:processors::resource::attributes: [{ key: service.name, action: insert, value: elastic-otel-test1 }]"},
			false,
		},
		{
			"otel config with set missing action field",
			[]string{filepath.Join("testdata", "otel", "otel.yml"), "yaml:processors::resource::attributes: [{ key: service.name, value: elastic-otel-test2 }]"},
			true,
		},
		{
			"otel config with set missing key field",
			[]string{filepath.Join("testdata", "otel", "otel.yml"), "yaml:processors::resource::attributes: [{ action: insert, value: elastic-otel-test3 }]"},
			true,
		},
		{
			"otel config with set missing key and action fields",
			[]string{filepath.Join("testdata", "otel", "otel.yml"), "yaml:processors::resource::attributes: [{ value: elastic-otel-test4 }]"},
			true,
		},
		{
			"agent config",
			[]string{filepath.Join("testdata", "otel", "elastic-agent.yml")},
			true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateOtelConfig(context.Background(), tc.ConfigPaths)

			if tc.ExpectingErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

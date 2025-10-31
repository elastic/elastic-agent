// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestEnableBeatsReceiversModifier(t *testing.T) {
	tests := []struct {
		name              string
		envValue          string
		inputType         string
		expectOtelRuntime bool
	}{
		{
			name:              "ENABLE_BEATS_RECEIVERS=1",
			envValue:          "1",
			inputType:         "filestream",
			expectOtelRuntime: true,
		},
		{
			name:              "ENABLE_BEATS_RECEIVERS=",
			envValue:          "",
			inputType:         "filestream",
			expectOtelRuntime: false,
		},
		{
			name:              "ENABLE_BEATS_RECEIVERS=invalid",
			envValue:          "invalid",
			inputType:         "filestream",
			expectOtelRuntime: false,
		},
		{
			name:              "unsupported input with ENABLE_BEATS_RECEIVERS=1",
			envValue:          "1",
			inputType:         "unsupported",
			expectOtelRuntime: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("ENABLE_BEATS_RECEIVERS", tt.envValue)
			} else {
				os.Unsetenv("ENABLE_BEATS_RECEIVERS")
			}
			defer os.Unsetenv("ENABLE_BEATS_RECEIVERS")

			testComp := component.Component{
				InputSpec: &component.InputRuntimeSpec{
					InputType: tt.inputType,
				},
				RuntimeManager: component.ProcessRuntimeManager,
				Units: []component.Unit{
					{
						ID:     "test-unit",
						Type:   client.UnitTypeInput,
						Config: component.MustExpectedConfig(map[string]interface{}{"test": "config"}),
					},
				},
			}

			comps := []component.Component{testComp}
			cfg := map[string]interface{}{}

			modifier := EnableBeatsReceivers()
			result, err := modifier(comps, cfg)
			require.NoError(t, err)

			require.Len(t, result, 1)
			resultComp := result[0]

			expectedRuntime := component.ProcessRuntimeManager
			if tt.expectOtelRuntime {
				expectedRuntime = component.OtelRuntimeManager
			}
			assert.Equal(t, expectedRuntime, resultComp.RuntimeManager)
		})
	}
}

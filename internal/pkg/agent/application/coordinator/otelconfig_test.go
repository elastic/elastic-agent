// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pipeline"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestSignalToDefaultDatastreamType(t *testing.T) {
	tests := []struct {
		signal        pipeline.Signal
		expectedType  string
		expectedError error
	}{
		{
			signal:       pipeline.SignalLogs,
			expectedType: "logs",
		},
		{
			signal:       pipeline.SignalMetrics,
			expectedType: "metrics",
		},
		{
			signal:        pipeline.SignalTraces,
			expectedError: fmt.Errorf("signal type not supported by Beats receivers: traces"),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("signal=%v", tt.signal), func(t *testing.T) {
			actualType, actualError := signalToDefaultDatastreamType(tt.signal)
			assert.Equal(t, tt.expectedType, actualType)

			if tt.expectedError != nil {
				assert.Error(t, actualError)
				assert.EqualError(t, actualError, tt.expectedError.Error())
			} else {
				assert.NoError(t, actualError)
			}
		})
	}
}

func TestGetSignalForComponent(t *testing.T) {
	tests := []struct {
		name           string
		component      component.Component
		expectedSignal pipeline.Signal
		expectedError  error
	}{
		{
			name:          "no input spec",
			component:     component.Component{InputType: "test"},
			expectedError: fmt.Errorf("input type not supported by Otel: %s", "test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSignal, actualError := getSignalForComponent(&tt.component)
			assert.Equal(t, tt.expectedSignal, actualSignal)

			if tt.expectedError != nil {
				assert.Error(t, actualError)
				assert.EqualError(t, actualError, tt.expectedError.Error())
			} else {
				assert.NoError(t, actualError)
			}
		})
	}
}

// TODO: Add unit tests for other config generation functions

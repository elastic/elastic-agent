// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions/handlers"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	componentruntime "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestPerformComponentDiagnostics(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		managerLogger: logger,
		components:    []component.Component{filebeatComp, otherComp},
	}

	expectedDiags := []componentruntime.ComponentDiagnostic{
		{
			Component: filebeatComp,
		},
		{
			Component: otherComp,
		},
	}

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	for i, d := range diags {
		assert.Equal(t, expectedDiags[i].Component.ID, d.Component.ID)
		// we should have errors set about not being able to connect to diagnostics extension
		require.NotNil(t, d.Err)
		assert.ErrorContains(t, d.Err, fmt.Sprintf("failed to get diagnostics for %s", d.Component.ID))
	}
}

func TestPerformDiagnostics(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		managerLogger: logger,
		components:    []component.Component{filebeatComp, otherComp},
	}

	t.Run("diagnose all units when no request is provided", func(t *testing.T) {
		expectedDiags := []componentruntime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[1],
			},
			{
				Component: otherComp,
				Unit:      otherComp.Units[0],
			},
			{
				Component: otherComp,
				Unit:      otherComp.Units[1],
			},
		}
		diags := m.PerformDiagnostics(t.Context())
		assert.Equal(t, expectedDiags, diags)
	})

	t.Run("diagnose specific unit", func(t *testing.T) {
		req := componentruntime.ComponentUnitDiagnosticRequest{
			Component: filebeatComp,
			Unit:      filebeatComp.Units[0],
		}
		expectedDiags := []componentruntime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
		}
		diags := m.PerformDiagnostics(t.Context(), req)
		assert.Equal(t, expectedDiags, diags)
	})
}

func TestBeatMetrics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skip test on Windows.",
			"It's technically cumbersome to set up an npipe http server.",
			"And it doesn't have anything to do with the code paths being tested.",
		)
	}
	setTemporaryAgentPath(t)
	logger, obs := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	m := &OTelManager{
		managerLogger: logger,
		components:    []component.Component{filebeatComp},
	}
	expectedMetricData, err := json.MarshalIndent(map[string]any{"test": "test"}, "", "  ")
	require.NoError(t, err)

	expectedResponse := elasticdiagnostics.Response{
		ComponentDiagnostics: []*proto.ActionDiagnosticUnitResult{
			{
				Name:        compID,
				Filename:    "beat_metrics.json",
				ContentType: "application/json",
				Description: "Metrics from the default monitoring namespace and expvar.",
				Content:     expectedMetricData,
			},
			{
				Name:        compID,
				Filename:    "input_metrics.json",
				ContentType: "application/json",
				Description: "Metrics from active inputs.",
				Content:     expectedMetricData,
			},
		},
	}

	called := false
	server := handlers.NewMockServer(t, paths.DiagnosticsExtensionSocket(), &called, &expectedResponse)
	t.Cleanup(func() {
		cErr := server.Close()
		assert.NoError(t, cErr)
	})

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	assert.Len(t, obs.All(), 0)
	require.Len(t, diags, 1)
	require.True(t, called)

	diag := diags[0]
	assert.Equal(t, filebeatComp, diag.Component)
	// two metrics diagnostics and one filebeat registry
	require.Len(t, diag.Results, 2, "expected 2 diagnostics, got error: %w", diag.Err)

	t.Run("stats beat metrics", func(t *testing.T) {
		beatMetrics := diag.Results[0]
		assert.Equal(t, compID, beatMetrics.Name)
		assert.Equal(t, "Metrics from the default monitoring namespace and expvar.", beatMetrics.Description)
		assert.Equal(t, "beat_metrics.json", beatMetrics.Filename)
		assert.Equal(t, "application/json", beatMetrics.ContentType)
		assert.Equal(t, expectedMetricData, beatMetrics.Content)
	})

	t.Run("input beat metrics", func(t *testing.T) {
		inputMetrics := diag.Results[1]
		assert.Equal(t, compID, inputMetrics.Name)
		assert.Equal(t, "Metrics from active inputs.", inputMetrics.Description)
		assert.Equal(t, "input_metrics.json", inputMetrics.Filename)
		assert.Equal(t, "application/json", inputMetrics.ContentType)
		assert.Equal(t, expectedMetricData, inputMetrics.Content)
	})
}

func setTemporaryAgentPath(t *testing.T) {
	topPath := paths.Top()
	tempTopPath := t.TempDir()
	paths.SetTop(tempTopPath)
	t.Cleanup(func() {
		paths.SetTop(topPath)
	})
}

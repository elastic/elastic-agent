// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"encoding/json"
	"net/http"
	"runtime"
	"testing"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions/handlers"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	componentruntime "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/ipc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestPerformComponentDiagnostics(t *testing.T) {
	setTemporaryAgentPath(t)
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
		{Component: filebeatComp},
		{Component: otherComp},
	}

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	require.Len(t, diags, len(expectedDiags))
	for i, d := range diags {
		assert.Equal(t, expectedDiags[i].Component.ID, d.Component.ID)
		assert.Nil(t, d.Err)
		assert.Empty(t, d.Results)
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

	filebeatComp := testComponent("filebeat-comp-1")
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	// The receiver name format must match what EDOT registers, otherwise the comp.ID extraction
	// in production would not find this result.
	receiverName := translate.GetReceiverID(otelcomponent.MustNewType("filebeatreceiver"), filebeatComp.ID+"/stream-1").String()

	m := &OTelManager{
		managerLogger: logger,
		components:    []component.Component{filebeatComp},
	}
	expectedMetricData, err := json.MarshalIndent(map[string]any{"test": "test"}, "", "  ")
	require.NoError(t, err)

	expectedResponse := elasticdiagnostics.Response{
		ComponentDiagnostics: []*proto.ActionDiagnosticUnitResult{
			{
				Name:        receiverName,
				Filename:    "beat_metrics.json",
				ContentType: "application/json",
				Description: "Metrics from the default monitoring namespace and expvar.",
				Content:     expectedMetricData,
			},
			{
				Name:        receiverName,
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

	compDiag := diags[0]
	assert.Equal(t, filebeatComp, compDiag.Component)
	require.Nil(t, compDiag.Err)
	require.Len(t, compDiag.Results, 2)

	t.Run("stats beat metrics", func(t *testing.T) {
		beatMetrics := compDiag.Results[0]
		assert.Equal(t, receiverName, beatMetrics.Name)
		assert.Equal(t, "Metrics from the default monitoring namespace and expvar.", beatMetrics.Description)
		assert.Equal(t, "beat_metrics.json", beatMetrics.Filename)
		assert.Equal(t, "application/json", beatMetrics.ContentType)
		assert.Equal(t, expectedMetricData, beatMetrics.Content)
	})

	t.Run("input beat metrics", func(t *testing.T) {
		inputMetrics := compDiag.Results[1]
		assert.Equal(t, receiverName, inputMetrics.Name)
		assert.Equal(t, "Metrics from active inputs.", inputMetrics.Description)
		assert.Equal(t, "input_metrics.json", inputMetrics.Filename)
		assert.Equal(t, "application/json", inputMetrics.ContentType)
		assert.Equal(t, expectedMetricData, inputMetrics.Content)
	})
}

// TestBeatMetricsPrefixOverlap guards that each EDOT result is assigned to exactly one component.
// When one component ID is a prefix of another (e.g. "filebeat" and "filebeat-2"), the prefix
// component must not receive the result of the longer one.
func TestBeatMetricsPrefixOverlap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skip test on Windows.",
			"It's technically cumbersome to set up an npipe http server.",
			"And it doesn't have anything to do with the code paths being tested.",
		)
	}
	setTemporaryAgentPath(t)
	logger, _ := loggertest.New("test")

	shortComp := testComponent("filebeat")
	shortComp.InputSpec.Spec.Command.Args = []string{"filebeat"}
	longComp := testComponent("filebeat-2")
	longComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	shortReceiver := translate.GetReceiverID(otelcomponent.MustNewType("filebeatreceiver"), shortComp.ID+"/stream-1").String()
	longReceiver := translate.GetReceiverID(otelcomponent.MustNewType("filebeatreceiver"), longComp.ID+"/stream-1").String()

	metricData, err := json.MarshalIndent(map[string]any{"test": "test"}, "", "  ")
	require.NoError(t, err)

	expectedResponse := elasticdiagnostics.Response{
		ComponentDiagnostics: []*proto.ActionDiagnosticUnitResult{
			{Name: shortReceiver, Filename: "beat_metrics.json", ContentType: "application/json", Content: metricData},
			{Name: longReceiver, Filename: "beat_metrics.json", ContentType: "application/json", Content: metricData},
		},
	}

	m := &OTelManager{
		managerLogger: logger,
		components:    []component.Component{shortComp, longComp},
	}

	called := false
	server := handlers.NewMockServer(t, paths.DiagnosticsExtensionSocket(), &called, &expectedResponse)
	t.Cleanup(func() {
		assert.NoError(t, server.Close())
	})

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	require.True(t, called)
	require.Len(t, diags, 2)

	// find results by component ID to avoid order dependence
	resultsByComp := make(map[string][]string)
	for _, d := range diags {
		for _, r := range d.Results {
			resultsByComp[d.Component.ID] = append(resultsByComp[d.Component.ID], r.Name)
		}
	}

	assert.Equal(t, []string{shortReceiver}, resultsByComp[shortComp.ID], "short comp must get only its own result")
	assert.Equal(t, []string{longReceiver}, resultsByComp[longComp.ID], "long comp must get only its own result")
}

// TestPerformComponentDiagnosticsUnexpectedError verifies that when EDOT returns an error other than
// "not running" (ENOENT/ECONNREFUSED), the error is recorded on each component and the call itself
// still returns nil so the rest of the diagnostics archive is produced.
func TestPerformComponentDiagnosticsUnexpectedError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skip test on Windows.",
			"It's technically cumbersome to set up an npipe http server.",
			"And it doesn't have anything to do with the code paths being tested.",
		)
	}
	setTemporaryAgentPath(t)
	managerLogger, obs := loggertest.New("test")

	filebeatComp := testComponent("filebeat-comp-1")
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}
	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		managerLogger: managerLogger,
		components:    []component.Component{filebeatComp, otherComp},
	}

	// A reachable socket that returns a non-JSON body makes PerformDiagnosticsExt fail while
	// unmarshalling. That error is neither ENOENT nor ECONNREFUSED, so it hits the unexpected path.
	mux := http.NewServeMux()
	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	l, err := ipc.CreateListener(managerLogger, paths.DiagnosticsExtensionSocket())
	require.NoError(t, err)
	server := &http.Server{Handler: mux} //nolint:gosec // This is a test
	go func() {
		assert.ErrorIs(t, server.Serve(l), http.ErrServerClosed)
	}()
	t.Cleanup(func() {
		assert.NoError(t, server.Close())
	})

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	require.Len(t, diags, 2)
	for _, d := range diags {
		assert.Error(t, d.Err)
		assert.Empty(t, d.Results)
	}

	assert.NotEmpty(t, obs.FilterLevelExact(zapcore.WarnLevel).FilterMessageSnippet("failed to fetch diagnostics from collector").All(), "unexpected error should be logged at warn level")
}

func setTemporaryAgentPath(t *testing.T) {
	topPath := paths.Top()
	tempTopPath := t.TempDir()
	paths.SetTop(tempTopPath)
	t.Cleanup(func() {
		paths.SetTop(topPath)
	})
}

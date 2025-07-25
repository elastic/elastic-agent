// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils/broadcaster"
)

func TestCoordinatorExpectedDiagnosticHooks(t *testing.T) {

	expected := []string{
		"agent-info",
		"local-config",
		"pre-config",
		"variables",
		"computed-config",
		"components-expected",
		"components-actual",
		"state",
		"otel",
		"otel-merged",
	}

	coord := &Coordinator{}
	hooks := diagnosticHooksMap(coord)
	assert.Equal(t, len(expected), len(hooks), "Wrong number of diagnostic hooks (did you forget to update diagnostics_test with your diagnostics change?)")
	for _, name := range expected {
		assert.Contains(t, hooks, name, "No hook returned for expected diagnostic %q", name)
	}
}

func TestDiagnosticLocalConfig(t *testing.T) {
	// Create a Coordinator with a test configuration and make sure the
	// local-config hook correctly returns it.
	cfg := &configuration.Configuration{
		Fleet: &configuration.FleetAgentConfig{
			Enabled:             true,
			AccessAPIKey:        "test-key",
			EnrollmentTokenHash: "test-enroll-hash",
			ReplaceTokenHash:    "test-replace-hash",
			Client: remote.Config{
				Protocol: "test-protocol",
			},
		},
		Settings: &configuration.SettingsConfig{
			MonitoringConfig: &monitoringCfg.MonitoringConfig{
				MonitorTraces: true,
				APM: monitoringCfg.APMConfig{
					Environment:  "diag-unit-test",
					APIKey:       "apikey",
					SecretToken:  "secret",
					Hosts:        []string{"host1", "host2"},
					GlobalLabels: map[string]string{"k1": "v1", "k2": "v2"},
					TLS: monitoringCfg.APMTLS{
						SkipVerify:        false,
						ServerCertificate: "/path/to/server/cert",
						ServerCA:          "/path/to/server/ca",
					},
				},
			},
		},
	}

	// The YAML we expect to see from the preceding config
	expectedCfg := `
agent:
  download: null
  grpc: null
  id: ""
  path: ""
  process: null
  reload: null
  upgrade: null
  v1_monitoring_enabled: false
  monitoring:
    enabled: false
    http: null
    logs: false
    metrics: false
    metrics_period: ""
    namespace: ""
    pprof: null
    failure_threshold: null
    traces: true
    apm:
      hosts:
        - host1
        - host2
      environment: diag-unit-test
      api_key: apikey
      secret_token: secret
      global_labels:
        k1: v1
        k2: v2
      tls:
        server_certificate: "/path/to/server/cert"
        server_ca: "/path/to/server/ca"
fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "test-enroll-hash"
  replace_token_hash: "test-replace-hash"
  agent:
  protocol: "test-protocol"
`

	coord := &Coordinator{cfg: cfg}
	hook, ok := diagnosticHooksMap(coord)["local-config"]
	require.True(t, ok, "diagnostic hooks should have an entry for local-config")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expectedCfg, string(result), "local-config diagnostic returned unexpected value")
}

func TestDiagnosticAgentInfo(t *testing.T) {
	// Create a coordinator with an info.Agent and ensure its included in diagnostics.

	coord := &Coordinator{agentInfo: fakeAgentInfo{
		agentID: "agent-id",
		headers: map[string]string{
			"header1": "value1",
			"header2": "value2",
		},
		logLevel: "trace",
		meta: &info.ECSMeta{
			Elastic: &info.ElasticECSMeta{
				Agent: &info.AgentECSMeta{
					BuildOriginal: "8.14.0-SNAPSHOT",
					ID:            "agent-id",
					LogLevel:      "trace",
					Snapshot:      true,
					Version:       "8.14.0",
					Unprivileged:  true,
					Upgradeable:   true,
				},
			},
			Host: &info.HostECSMeta{
				Arch:     "arm64",
				Hostname: "Test-Macbook-Pro.local",
			},
			OS: &info.SystemECSMeta{
				Name:     "macos",
				Platform: "darwin",
			},
		},
	}}

	expected := `
headers:
  header1: value1
  header2: value2
log_level: trace
log_level_raw: trace
metadata:
  elastic:
    agent:
      buildoriginal: "8.14.0-SNAPSHOT"
      complete: false
      fips: false
      id: agent-id
      loglevel: trace
      snapshot: true
      unprivileged: true
      upgradeable: true
      version: 8.14.0
  host:
    arch: arm64
    hostname: Test-Macbook-Pro.local
    name: ""
    id: ""
    ip: []
    mac: []
  os:
    family: ""
    kernel: ""
    platform: darwin
    version: ""
    name: macos
    fullname: ""
`

	hook, ok := diagnosticHooksMap(coord)["agent-info"]
	require.True(t, ok, "diagnostic hooks should have an entry for agent-info")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "agent-info diagnostic returned unexpected value")
}

func TestDiagnosticPreConfig(t *testing.T) {
	// Create a coordinator with a test AST and make sure it's returned
	// by the pre-config diagnostic.

	cfgStr := `
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`
	cfgMap := mapFromRawYAML(t, cfgStr)
	cfgAST, err := transpiler.NewAST(cfgMap)
	require.NoError(t, err, "Couldn't create test AST")

	coord := &Coordinator{ast: cfgAST}

	hook, ok := diagnosticHooksMap(coord)["pre-config"]
	require.True(t, ok, "diagnostic hooks should have an entry for pre-config")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, cfgStr, string(result), "pre-config diagnostic returned unexpected value")
}

func TestDiagnosticVariables(t *testing.T) {
	vars, err := transpiler.NewVars(
		"id",
		map[string]interface{}{
			"testvar": "testvalue",
		},
		nil, "")
	require.NoError(t, err)

	expected := `
variables:
  - testvar: testvalue
`

	coord := &Coordinator{vars: []*transpiler.Vars{vars}}

	hook, ok := diagnosticHooksMap(coord)["variables"]
	require.True(t, ok, "diagnostic hooks should have an entry for variables")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "variables diagnostic returned unexpected value")
}

func TestDiagnosticComputedConfig(t *testing.T) {
	// Create a Coordinator with a test value in derivedConfig and make sure
	// it's reported by the computed-config diagnostic.

	expected := `
test:
  values:
    type: elasticsearch
something:
  - id: thing one
  - id: thing two
`
	derivedCfg := mapFromRawYAML(t, expected)
	coord := &Coordinator{derivedConfig: derivedCfg}

	hook, ok := diagnosticHooksMap(coord)["computed-config"]
	require.True(t, ok, "diagnostic hooks should have an entry for computed-config")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "computed-config diagnostic returned unexpected value")
}

func TestDiagnosticComponentsExpected(t *testing.T) {
	// Create a Coordinator with a test component model and make sure it's
	// reported by the components-expected diagnostic
	components := []component.Component{
		{
			ID:         "filestream-component",
			InputType:  "filestream",
			OutputType: "elasticsearch",
			InputSpec: &component.InputRuntimeSpec{
				InputType:  "filestream",
				BinaryName: "filestream-binary",
				BinaryPath: "filestream-path",
				Spec: component.InputSpec{
					Name:        "filestream-spec",
					Description: "filestream description",
				},
			},
			Units: []component.Unit{
				{ID: "filestream-input", Type: client.UnitTypeInput, LogLevel: 2},
				{ID: "filestream-output", Type: client.UnitTypeOutput, LogLevel: 2},
			},
		},
	}

	expected := `
components:
  - id: filestream-component
    input_type: filestream
    output_type: elasticsearch
    input_spec:
      binary_name: filestream-binary
      binary_path: filestream-path
      input_type: filestream
      spec:
        name: filestream-spec
        description: "filestream description"
        platforms: []
    units:
      - id: filestream-input
        log_level: 2
        type: 0
      - id: filestream-output
        log_level: 2
        type: 1
`

	coord := &Coordinator{componentModel: components}

	hook, ok := diagnosticHooksMap(coord)["components-expected"]
	require.True(t, ok, "diagnostic hooks should have an entry for components-expected")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "components-expected diagnostic returned unexpected value")
}

func TestDiagnosticComponentsExpectedWithAPM(t *testing.T) {
	// Create a Coordinator with a test component model and make sure it's
	// reported by the components-expected diagnostic
	components := []component.Component{
		{
			ID:         "some-apm-aware-component",
			InputType:  "filestream",
			OutputType: "elasticsearch",
			Component: &proto.Component{
				ApmConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment:  "diag-unit-test",
						ApiKey:       "apikey",
						SecretToken:  "st",
						Hosts:        []string{"host1", "host2"},
						GlobalLabels: "k=v",
						Tls: &proto.ElasticAPMTLS{
							SkipVerify: true,
							ServerCert: "servercert",
							ServerCa:   "serverca",
						},
					},
				},
			},
		},
	}

	expected := `
components:
  - id: some-apm-aware-component
    input_type: filestream
    output_type: elasticsearch
    units: []
    component:
      limits: null
      apmconfig:
        elastic:
          environment: diag-unit-test
          apikey: apikey
          secrettoken: st
          globallabels: "k=v"
          hosts:
          - host1
          - host2
          tls:
            skipverify: true
            servercert: servercert
            serverca: serverca
          samplingrate: null
`

	coord := &Coordinator{componentModel: components}

	hook, ok := diagnosticHooksMap(coord)["components-expected"]
	require.True(t, ok, "diagnostic hooks should have an entry for components-expected")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "components-expected diagnostic returned unexpected value")
}

func TestDiagnosticComponentsActual(t *testing.T) {
	// Create a Coordinator with observed component data in the state broadcaster
	// and make sure the components-actual diagnostic reports it
	state := State{
		Components: []runtime.ComponentComponentState{
			{
				Component: component.Component{
					ID:         "component-1",
					Err:        errors.New("component error"),
					InputType:  "test-input",
					OutputType: "test-output",
					Units: []component.Unit{
						{
							ID:       "test-unit",
							Type:     client.UnitTypeInput,
							LogLevel: 1,
							Err:      errors.New("unit error"),
						},
					},
				},
				State: runtime.ComponentState{
					State:   client.UnitStateFailed,
					Message: "error running component",
					Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
						{
							UnitType: client.UnitTypeInput,
							UnitID:   "test-unit",
						}: {State: client.UnitStateFailed},
					},
				},
			},
		},
	}

	expected := `
components:
  - id: component-1
    error: "component error"
    input_type: "test-input"
    output_type: "test-output"
    units:
      - id: test-unit
        error: {}
        log_level: 1
        type: 0
`

	coord := &Coordinator{
		// This test needs a broadcaster since the components-actual diagnostic
		// fetches the state via State().
		stateBroadcaster: broadcaster.New(state, 0, 0),
	}

	hook, ok := diagnosticHooksMap(coord)["components-actual"]
	require.True(t, ok, "diagnostic hooks should have an entry for components-actual")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "components-actual diagnostic returned unexpected value")
}

// TestDiagnosticState creates a coordinator with a test state and verify that
// the state diagnostic reports it.
func TestDiagnosticState(t *testing.T) {
	now := time.Now().UTC()
	state := State{
		State:        agentclient.Starting,
		Message:      "starting up",
		FleetState:   agentclient.Configuring,
		FleetMessage: "configuring",
		LogLevel:     1,
		Components: []runtime.ComponentComponentState{
			{
				Component: component.Component{ID: "comp-1"},
				State: runtime.ComponentState{
					State:   client.UnitStateDegraded,
					Message: "degraded message",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      "version name",
						BuildHash: "a-build-hash",
					},
				},
			},
		},
		UpgradeDetails: &details.Details{
			TargetVersion: "8.12.0",
			State:         "UPG_DOWNLOADING",
			ActionID:      "foobar",
			Metadata: details.Metadata{
				DownloadPercent: 0.17469,
				ScheduledAt:     &now,
				DownloadRate:    123.56,
				RetryUntil:      &now,
			},
		},
	}

	expected := fmt.Sprintf(`
state: 0
message: "starting up"
fleet_state: 1
fleet_message: "configuring"
log_level: "warning"
components:
  - id: "comp-1"
    state:
      pid: 0
      state: 3
      message: "degraded message"
      features_idx: 0
      component_idx: 0
      units: {}
      version_info:
        name: "version name"
        build_hash: "a-build-hash"
upgrade_details:
  target_version: 8.12.0
  state: UPG_DOWNLOADING
  action_id: foobar
  metadata:
    download_percent: 0.17469
    scheduled_at: %s
    download_rate: 123.56
    retry_until: %s
`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))

	coord := &Coordinator{
		// This test needs a broadcaster since the components-actual diagnostic
		// fetches the state via State().
		stateBroadcaster: broadcaster.New(state, 0, 0),
	}

	hook, ok := diagnosticHooksMap(coord)["state"]
	require.True(t, ok, "diagnostic hooks should have an entry for state")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "state diagnostic returned unexpected value")
}

func TestDiagnosticStateForAPM(t *testing.T) {
	// Create a coordinator with a test state and verify that the state
	// diagnostic reports it

	token := "st"
	state := State{
		State:        agentclient.Starting,
		Message:      "starting up",
		FleetState:   agentclient.Configuring,
		FleetMessage: "configuring",
		LogLevel:     1,
		Components: []runtime.ComponentComponentState{
			{
				Component: component.Component{ID: "comp-1"},
				State: runtime.ComponentState{
					State:   client.UnitStateDegraded,
					Message: "degraded message",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      "version name",
						BuildHash: "a-build-hash",
					},
					Component: &proto.Component{
						ApmConfig: &proto.APMConfig{
							Elastic: &proto.ElasticAPM{
								Environment: "diag-state-ut",
								SecretToken: token,
								Hosts:       []string{"apmhost"},
								Tls: &proto.ElasticAPMTLS{
									SkipVerify: true,
									ServerCert: "sc",
									ServerCa:   "sca",
								},
							},
						},
					},
					ComponentIdx: 1,
				},
			},
		},
	}

	expected := `
state: 0
message: "starting up"
fleet_state: 1
fleet_message: "configuring"
log_level: "warning"
components:
  - id: "comp-1"
    state:
      pid: 0
      state: 3
      message: "degraded message"
      features_idx: 0
      units: {}
      version_info:
        name: "version name"
        build_hash: "a-build-hash"
      component:
        apmconfig:
          elastic:
            apikey: ""
            environment: diag-state-ut
            hosts: [apmhost]
            secrettoken: st
            globallabels: ""
            tls:
              skipverify: true
              serverca: sca
              servercert: sc
            samplingrate: null
        limits: null
      component_idx: 1
`

	coord := &Coordinator{
		// This test needs a broadcaster since the components-actual diagnostic
		// fetches the state via State().
		stateBroadcaster: broadcaster.New(state, 0, 0),
	}

	hook, ok := diagnosticHooksMap(coord)["state"]
	require.True(t, ok, "diagnostic hooks should have an entry for state")

	result := hook.Hook(context.Background())
	assert.YAMLEq(t, expected, string(result), "state diagnostic returned unexpected value")
}

// Fetch the diagnostic hooks and add them to a lookup table for
// easier verification
func diagnosticHooksMap(coord *Coordinator) map[string]diagnostics.Hook {
	diagHooks := coord.DiagnosticHooks()
	hooksMap := map[string]diagnostics.Hook{}
	for i, h := range diagHooks {
		hooksMap[h.Name] = diagHooks[i]
	}
	return hooksMap
}

func mapFromRawYAML(t *testing.T, str string) map[string]interface{} {
	var result map[string]interface{}
	err := yaml.Unmarshal([]byte(str), &result)
	require.NoError(t, err, "Parsing of YAML test string must succeed")
	return result
}

type fakeAgentInfo struct {
	agentID      string
	headers      map[string]string
	logLevel     string
	snapshot     bool
	version      string
	unprivileged bool
	isStandalone bool
	meta         *info.ECSMeta
}

func (a fakeAgentInfo) AgentID() string {
	return a.agentID
}

func (a fakeAgentInfo) Headers() map[string]string {
	return a.headers
}

func (a fakeAgentInfo) LogLevel() string {
	return a.logLevel
}

func (a fakeAgentInfo) RawLogLevel() string {
	return a.logLevel
}

func (a fakeAgentInfo) Snapshot() bool {
	return a.snapshot
}

func (a fakeAgentInfo) Version() string {
	return a.version
}

func (a fakeAgentInfo) Unprivileged() bool {
	return a.unprivileged
}

func (a fakeAgentInfo) IsStandalone() bool {
	return a.isStandalone
}

func (a fakeAgentInfo) ECSMetadata(l *logger.Logger) (*info.ECSMeta, error) {
	return a.meta, nil
}

func (a fakeAgentInfo) ReloadID(ctx context.Context) error                  { panic("implement me") }
func (a fakeAgentInfo) SetLogLevel(ctx context.Context, level string) error { panic("implement me") }

func TestCoordinatorPerformDiagnostics(t *testing.T) {
	tests := []struct {
		name                     string
		runtimeDiags             []runtime.ComponentUnitDiagnostic
		otelDiags                []runtime.ComponentUnitDiagnostic
		expectedRuntimeDiagCount int
		expectedOtelDiagCount    int
	}{
		{
			name: "both runtime and otel return diagnostics",
			runtimeDiags: []runtime.ComponentUnitDiagnostic{
				{
					Component: component.Component{ID: "runtime-comp-1"},
					Unit:      component.Unit{ID: "runtime-unit-1", Type: client.UnitTypeInput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "runtime-diag"}},
				},
			},
			otelDiags: []runtime.ComponentUnitDiagnostic{
				{
					Component: component.Component{ID: "otel-comp-1"},
					Unit:      component.Unit{ID: "otel-unit-1", Type: client.UnitTypeOutput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "otel-diag"}},
				},
			},
			expectedRuntimeDiagCount: 1,
			expectedOtelDiagCount:    1,
		},
		{
			name: "only runtime returns diagnostics",
			runtimeDiags: []runtime.ComponentUnitDiagnostic{
				{
					Component: component.Component{ID: "runtime-comp-1"},
					Unit:      component.Unit{ID: "runtime-unit-1", Type: client.UnitTypeInput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "runtime-diag"}},
				},
			},
			otelDiags:                []runtime.ComponentUnitDiagnostic{},
			expectedRuntimeDiagCount: 1,
			expectedOtelDiagCount:    0,
		},
		{
			name:         "only otel returns diagnostics",
			runtimeDiags: []runtime.ComponentUnitDiagnostic{},
			otelDiags: []runtime.ComponentUnitDiagnostic{
				{
					Component: component.Component{ID: "otel-comp-1"},
					Unit:      component.Unit{ID: "otel-unit-1", Type: client.UnitTypeOutput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "otel-diag"}},
				},
			},
			expectedRuntimeDiagCount: 0,
			expectedOtelDiagCount:    1,
		},
		{
			name:                     "no diagnostics from either manager",
			runtimeDiags:             []runtime.ComponentUnitDiagnostic{},
			otelDiags:                []runtime.ComponentUnitDiagnostic{},
			expectedRuntimeDiagCount: 0,
			expectedOtelDiagCount:    0,
		},
		{
			name: "multiple diagnostics from both managers",
			runtimeDiags: []runtime.ComponentUnitDiagnostic{
				{
					Component: component.Component{ID: "runtime-comp-1"},
					Unit:      component.Unit{ID: "runtime-unit-1", Type: client.UnitTypeInput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "runtime-diag-1"}},
				},
				{
					Component: component.Component{ID: "runtime-comp-2"},
					Unit:      component.Unit{ID: "runtime-unit-2", Type: client.UnitTypeInput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "runtime-diag-2"}},
				},
			},
			otelDiags: []runtime.ComponentUnitDiagnostic{
				{
					Component: component.Component{ID: "otel-comp-1"},
					Unit:      component.Unit{ID: "otel-unit-1", Type: client.UnitTypeOutput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "otel-diag-1"}},
				},
				{
					Component: component.Component{ID: "otel-comp-2"},
					Unit:      component.Unit{ID: "otel-unit-2", Type: client.UnitTypeOutput},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "otel-diag-2"}},
				},
			},
			expectedRuntimeDiagCount: 2,
			expectedOtelDiagCount:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock managers with callbacks
			mockRuntimeMgr := &fakeRuntimeManager{
				performDiagnosticsCallback: func(
					ctx context.Context,
					reqs ...runtime.ComponentUnitDiagnosticRequest,
				) []runtime.ComponentUnitDiagnostic {
					return tt.runtimeDiags
				},
			}
			mockOtelMgr := &fakeOTelManager{
				performDiagnosticsCallback: func(
					ctx context.Context,
					reqs ...runtime.ComponentUnitDiagnosticRequest,
				) []runtime.ComponentUnitDiagnostic {
					return tt.otelDiags
				},
			}

			// Create coordinator with mock managers
			coord := &Coordinator{
				runtimeMgr: mockRuntimeMgr,
				otelMgr:    mockOtelMgr,
			}

			// Create test requests
			req1 := runtime.ComponentUnitDiagnosticRequest{
				Component: component.Component{ID: "test-comp-1"},
				Unit:      component.Unit{ID: "test-unit-1", Type: client.UnitTypeInput},
			}
			req2 := runtime.ComponentUnitDiagnosticRequest{
				Component: component.Component{ID: "test-comp-2"},
				Unit:      component.Unit{ID: "test-unit-2", Type: client.UnitTypeOutput},
			}

			// Execute PerformDiagnostics
			ctx := context.Background()
			result := coord.PerformDiagnostics(ctx, req1, req2)

			// Verify results
			runtimeDiagFound := 0
			otelDiagFound := 0
			for _, diag := range result {
				if diag.Component.ID == "runtime-comp-1" || diag.Component.ID == "runtime-comp-2" {
					runtimeDiagFound++
				}
				if diag.Component.ID == "otel-comp-1" || diag.Component.ID == "otel-comp-2" {
					otelDiagFound++
				}
			}
			assert.Equal(t, tt.expectedRuntimeDiagCount, runtimeDiagFound, "Runtime diagnostic count should match expected")
			assert.Equal(t, tt.expectedOtelDiagCount, otelDiagFound, "OTel diagnostic count should match expected")
		})
	}
}

func TestCoordinatorPerformComponentDiagnostics(t *testing.T) {
	tests := []struct {
		name                     string
		runtimeDiags             []runtime.ComponentDiagnostic
		runtimeErr               error
		otelDiags                []runtime.ComponentDiagnostic
		otelErr                  error
		expectedRuntimeDiagCount int
		expectedOtelDiagCount    int
	}{
		{
			name: "both runtime and otel return diagnostics successfully",
			runtimeDiags: []runtime.ComponentDiagnostic{
				{
					Component: component.Component{ID: "runtime-comp-1"},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "runtime-diag"}},
				},
			},
			otelDiags: []runtime.ComponentDiagnostic{
				{
					Component: component.Component{ID: "otel-comp-1"},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "otel-diag"}},
				},
			},
			expectedRuntimeDiagCount: 1,
			expectedOtelDiagCount:    1,
		},
		{
			name:         "runtime manager returns error",
			runtimeDiags: []runtime.ComponentDiagnostic{},
			runtimeErr:   errors.New("runtime manager error"),
			otelDiags: []runtime.ComponentDiagnostic{
				{
					Component: component.Component{ID: "otel-comp-1"},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "otel-diag"}},
				},
			},
			expectedRuntimeDiagCount: 0,
			expectedOtelDiagCount:    1,
		},
		{
			name: "otel manager returns error",
			runtimeDiags: []runtime.ComponentDiagnostic{
				{
					Component: component.Component{ID: "runtime-comp-1"},
					Results:   []*proto.ActionDiagnosticUnitResult{{Name: "runtime-diag"}},
				},
			},
			otelDiags:                []runtime.ComponentDiagnostic{},
			otelErr:                  errors.New("otel manager error"),
			expectedRuntimeDiagCount: 1,
			expectedOtelDiagCount:    0,
		},
		{
			name:                     "only runtime returns diagnostics",
			runtimeDiags:             []runtime.ComponentDiagnostic{{Component: component.Component{ID: "runtime-comp-1"}}},
			otelDiags:                []runtime.ComponentDiagnostic{},
			expectedRuntimeDiagCount: 1,
			expectedOtelDiagCount:    0,
		},
		{
			name:                     "only otel returns diagnostics",
			runtimeDiags:             []runtime.ComponentDiagnostic{},
			otelDiags:                []runtime.ComponentDiagnostic{{Component: component.Component{ID: "otel-comp-1"}}},
			expectedRuntimeDiagCount: 0,
			expectedOtelDiagCount:    1,
		},
		{
			name:                     "no diagnostics from either manager",
			runtimeDiags:             []runtime.ComponentDiagnostic{},
			otelDiags:                []runtime.ComponentDiagnostic{},
			expectedRuntimeDiagCount: 0,
			expectedOtelDiagCount:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock managers with callbacks
			mockRuntimeMgr := &fakeRuntimeManager{
				performComponentDiagnosticsCallback: func(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, comps ...component.Component) ([]runtime.ComponentDiagnostic, error) {
					return tt.runtimeDiags, tt.runtimeErr
				},
			}
			mockOtelMgr := &fakeOTelManager{
				performComponentDiagnosticsCallback: func(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, comps ...component.Component) ([]runtime.ComponentDiagnostic, error) {
					return tt.otelDiags, tt.otelErr
				},
			}

			// Create coordinator with mock managers
			coord := &Coordinator{
				runtimeMgr: mockRuntimeMgr,
				otelMgr:    mockOtelMgr,
			}

			// Create test components and additional metrics
			comp1 := component.Component{ID: "test-comp-1"}
			comp2 := component.Component{ID: "test-comp-2"}
			additionalMetrics := []cproto.AdditionalDiagnosticRequest{
				cproto.AdditionalDiagnosticRequest_CPU,
				cproto.AdditionalDiagnosticRequest_CONN,
			}

			// Execute PerformComponentDiagnostics
			ctx := context.Background()
			result, err := coord.PerformComponentDiagnostics(ctx, additionalMetrics, comp1, comp2)

			// Verify error handling
			if tt.otelErr != nil {
				assert.ErrorIs(t, err, tt.otelErr, "Returned error should include otel manager error")
			}
			if tt.runtimeErr != nil {
				assert.ErrorIs(t, err, tt.runtimeErr, "Returned error should include runtime manager error")
			}

			// Verify results
			runtimeDiagFound := 0
			otelDiagFound := 0
			for _, diag := range result {
				if diag.Component.ID == "runtime-comp-1" {
					runtimeDiagFound++
				}
				if diag.Component.ID == "otel-comp-1" {
					otelDiagFound++
				}
			}
			assert.Equal(t, tt.expectedRuntimeDiagCount, runtimeDiagFound, "Runtime diagnostic count should match expected")
			assert.Equal(t, tt.expectedOtelDiagCount, otelDiagFound, "OTel diagnostic count should match expected")
		})
	}
}

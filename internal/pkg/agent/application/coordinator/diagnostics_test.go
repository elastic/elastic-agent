// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
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
			Enabled:      true,
			AccessAPIKey: "test-key",
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
    namespace: ""
    pprof: null
    traces: true
    apm:
      hosts:
        - host1
        - host2
      environment: diag-unit-test
      apikey: apikey
      secrettoken: secret
      globallabels:
        k1: v1
        k2: v2
      tls:
        skipverify: false
        servercertificate: "/path/to/server/cert"
        serverca: "/path/to/server/ca"
fleet:
  enabled: true
  access_api_key: "test-key"
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
		logLevel:     "trace",
		snapshot:     true,
		version:      "8.14.0",
		unprivileged: true,
	}}

	expected := `
agent_id: agent-id
headers:
  header1: value1
  header2: value2
log_level: trace
snapshot: true
version: 8.14.0
unprivileged: true
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
		nil)
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
		{
			ID:         "shipper-component",
			OutputType: "elasticsearch",
			ShipperSpec: &component.ShipperRuntimeSpec{
				ShipperType: "shipper",
				BinaryName:  "shipper-binary",
				BinaryPath:  "shipper-path",
				Spec: component.ShipperSpec{
					Name:        "shipper-spec",
					Description: "shipper description",
				},
			},
			Units: []component.Unit{
				{ID: "shipper-input", Type: client.UnitTypeInput, LogLevel: 3},
				{ID: "shipper-output", Type: client.UnitTypeOutput, LogLevel: 3},
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
  - id: shipper-component
    input_type: ""
    output_type: elasticsearch
    shipper_spec:
      binary_name: shipper-binary
      binary_path: shipper-path
      shipper_type: shipper
      spec:
        name: shipper-spec
        description: "shipper description"
        outputs: []
        platforms: []
    units:
      - id: shipper-input
        log_level: 3
        type: 0
      - id: shipper-output
        log_level: 3
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

func (a fakeAgentInfo) Snapshot() bool {
	return a.snapshot
}

func (a fakeAgentInfo) Version() string {
	return a.version
}

func (a fakeAgentInfo) Unprivileged() bool {
	return a.unprivileged
}

func (a fakeAgentInfo) ReloadID(ctx context.Context) error                  { panic("implement me") }
func (a fakeAgentInfo) SetLogLevel(ctx context.Context, level string) error { panic("implement me") }

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringcfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestMonitoringFull(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")
	testMon := BeatsMonitor{
		enabled: true,
		config: &monitoringConfig{
			C: &monitoringcfg.MonitoringConfig{
				Enabled:        true,
				MonitorMetrics: true,
				MonitorLogs:    true,
				HTTP: &monitoringcfg.MonitoringHTTPConfig{
					Enabled: true,
				},
				RuntimeManager: monitoringcfg.DefaultRuntimeManager,
			},
		},
		agentInfo: agentInfo,
	}

	policy := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"metrics": true,
				"http": map[string]any{
					"enabled": false,
				},
			},
		},
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	// Add a Service component with a set log path to test the special logic for generating monitoring config for them
	// The rest of the logic is covered by the monitoring components monitoring themselves
	compList := []component.Component{
		{
			ID: "endpoint-default",
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Command: &component.CommandSpec{
						Name: "endpoint-security",
					},
					Service: &component.ServiceSpec{
						CPort: 7688,
						Log: &component.ServiceLogSpec{
							Path: "/var/log/endpoint.log",
						},
					},
				},
			},
		},
		{
			ID: "filebeat-default",
			InputSpec: &component.InputRuntimeSpec{
				BinaryName: "filebeat",
			},
			RuntimeManager: component.DefaultRuntimeManager,
		},
		{
			ID: "filestream-otel",
			InputSpec: &component.InputRuntimeSpec{
				BinaryName: "filebeat",
			},
			RuntimeManager: component.OtelRuntimeManager,
		},
	}

	existingPidStateMap := map[string]uint64{
		"endpoint-default": 1234,
	}

	expectedConfigFilePath := filepath.Join(".", "testdata", "monitoring_config_full.yaml")
	expectedConfigBytes, err := os.ReadFile(expectedConfigFilePath)
	require.NoError(t, err)

	outCfg, err := testMon.MonitoringConfig(policy, compList, existingPidStateMap)
	require.NoError(t, err)

	// Replace paths with placeholders. Log paths are different for each OS and it's annoying to fully account for the
	// differences in this test. Same thing applies to endpoints.
	for _, inputCfg := range outCfg["inputs"].([]any) {
		inputCfgMap := inputCfg.(map[string]interface{})
		streams := inputCfgMap["streams"].([]interface{})
		for _, stream := range streams {
			streamMap := stream.(map[string]interface{})
			if _, ok := streamMap["paths"]; ok {
				streamMap["paths"] = []string{"placeholder"}
			}
			if _, ok := streamMap["hosts"]; ok {
				streamMap["hosts"] = []string{"placeholder"}
			}
		}
	}

	outCfgBytes, err := yaml.Marshal(outCfg)
	require.NoError(t, err)
	outCfgString := string(outCfgBytes)
	// replace the version with a placeholder
	outCfgString = strings.ReplaceAll(outCfgString, agentInfo.Version(), "placeholder")
	assert.Equal(t, string(expectedConfigBytes), outCfgString)
}

func TestMonitoringWithEndpoint(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	testMon := BeatsMonitor{
		enabled: true,
		config: &monitoringConfig{
			C: &monitoringcfg.MonitoringConfig{
				Enabled:        true,
				MonitorMetrics: true,
				HTTP: &monitoringcfg.MonitoringHTTPConfig{

					Enabled: true,
				},
			},
		},
		agentInfo: agentInfo,
	}

	policy := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"metrics": true,
				"http": map[string]any{
					"enabled": false,
				},
			},
		},
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	// manually declaring all the MonitoringConfig() args since there's a lot of them, and this makes
	// the test a little more self-describing

	compList := []component.Component{
		{
			ID: "endpoint-default",
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Command: &component.CommandSpec{
						Name: "endpoint-security",
					},
					Service: &component.ServiceSpec{
						CPort: 7688,
					},
				},
			},
		},
		{
			ID: "filebeat-default",
			InputSpec: &component.InputRuntimeSpec{
				BinaryName: "filebeat",
			},
		},
	}

	existingPidStateMap := map[string]uint64{
		"endpoint-default": 1234,
	}

	outCfg, err := testMon.MonitoringConfig(policy, compList, existingPidStateMap)
	require.NoError(t, err)

	inputCfg := outCfg["inputs"].([]interface{})

	foundConfig := false

	for _, cfg := range inputCfg {
		unwrappedCfg := cfg.(map[string]interface{})
		if idName, ok := unwrappedCfg["id"]; ok && idName == "metrics-monitoring-endpoint_security" {
			foundConfig = true
			for compName, compCfg := range unwrappedCfg {
				if compName == "streams" {
					streamCfgUnwrapped := compCfg.([]interface{})
					for _, streamCfg := range streamCfgUnwrapped {
						streamValues := streamCfg.(map[string]interface{})
						require.Equal(t, []interface{}{"process"}, streamValues["metricsets"])
						require.Equal(t, "metrics-elastic_agent.endpoint_security-default", streamValues["index"])
						require.Equal(t, uint64(1234), streamValues["process.pid"])
					}
				}

			}
		}
	}

	require.True(t, foundConfig)
}

func TestMonitoringConfigMetricsInterval(t *testing.T) {

	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")
	components := []component.Component{{ID: "foobeat", InputSpec: &component.InputRuntimeSpec{BinaryName: "filebeat"}}}

	tcs := []struct {
		name             string
		monitoringCfg    *monitoringConfig
		policy           map[string]any
		expectedInterval time.Duration
	}{
		{
			name: "default metrics interval",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedInterval: defaultMetricsCollectionInterval,
		},
		{
			name: "agent config metrics interval",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					MetricsPeriod: "20s",
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedInterval: 20 * time.Second,
		},
		{
			name: "policy metrics interval",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					MetricsPeriod: "20s",
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						"metrics_period": "10s",
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedInterval: 10 * time.Second,
		},
	}

	for _, tc := range tcs {

		t.Run(tc.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled:         true,
				config:          tc.monitoringCfg,
				operatingSystem: runtime.GOOS,
				agentInfo:       agentInfo,
			}
			got, err := b.MonitoringConfig(tc.policy, components, map[string]uint64{}) // put a componentID/binary mapping to have something in the beats monitoring input
			assert.NoError(t, err)

			rawInputs, ok := got["inputs"]
			require.True(t, ok, "monitoring config contains no input")
			inputs, ok := rawInputs.([]any)
			require.True(t, ok, "monitoring inputs are not a list")
			marshaledInputs, err := yaml.Marshal(inputs)
			if assert.NoError(t, err, "error marshaling monitoring inputs") {
				t.Logf("marshaled monitoring inputs:\n%s\n", marshaledInputs)
			}

			// loop over the created inputs
			for _, i := range inputs {
				input, ok := i.(map[string]any)
				if assert.Truef(t, ok, "input is not represented as a map: %v", i) {
					inputID := input["id"]
					t.Logf("input %q", inputID)
					// check the streams created for the input, should be a list of objects
					if assert.Contains(t, input, "streams", "input %q does not contain any stream", inputID) &&
						assert.IsTypef(t, []any{}, input["streams"], "streams for input %q are not a list of objects", inputID) {
						// loop over streams and access keys
						for _, rawStream := range input["streams"].([]any) {
							if assert.IsTypef(t, map[string]any{}, rawStream, "stream %v for input %q is not a map", rawStream, inputID) {
								stream := rawStream.(map[string]any)
								// check period and assert its value
								streamID := stream["id"]
								if assert.Containsf(t, stream, "period", "stream %q for input %q does not contain a period", streamID, inputID) &&
									assert.IsType(t, "", stream["period"], "period for stream %q of input %q is not represented as a string", streamID, inputID) {
									periodString := stream["period"].(string)
									duration, err := time.ParseDuration(periodString)
									if assert.NoErrorf(t, err, "Unparseable period duration %s for stream %q of input %q", periodString, streamID, inputID) {
										assert.Equalf(t, duration, tc.expectedInterval, "unexpected duration for stream %q of input %q", streamID, inputID)
									}
								}
							}
						}
					}
				}
			}
		})
	}
}

func TestMonitoringConfigMetricsFailureThreshold(t *testing.T) {

	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")
	components := []component.Component{{ID: "foobeat", InputSpec: &component.InputRuntimeSpec{BinaryName: "filebeat"}}}

	sampleSevenErrorsStreamThreshold := uint(7)
	sampleTenErrorsStreamThreshold := uint(10)

	tcs := []struct {
		name              string
		monitoringCfg     *monitoringConfig
		policy            map[string]any
		expectedThreshold uint
	}{
		{
			name: "default failure threshold",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: defaultMetricsStreamFailureThreshold,
		},
		{
			name: "agent config failure threshold",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: &sampleSevenErrorsStreamThreshold,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: sampleSevenErrorsStreamThreshold,
		},
		{
			name: "policy failure threshold uint",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: &sampleSevenErrorsStreamThreshold,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: sampleTenErrorsStreamThreshold,
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: sampleTenErrorsStreamThreshold,
		},
		{
			name: "policy failure threshold int",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: &sampleSevenErrorsStreamThreshold,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: 10,
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: sampleTenErrorsStreamThreshold,
		},
		{
			name: "policy failure threshold string",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: &sampleSevenErrorsStreamThreshold,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: "10",
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: sampleTenErrorsStreamThreshold,
		},
		{
			name: "policy failure threshold float64",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: &sampleSevenErrorsStreamThreshold,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: float64(10),
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: sampleTenErrorsStreamThreshold,
		},
	}

	for _, tc := range tcs {

		t.Run(tc.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled:         true,
				config:          tc.monitoringCfg,
				operatingSystem: runtime.GOOS,
				agentInfo:       agentInfo,
			}
			got, err := b.MonitoringConfig(tc.policy, components, map[string]uint64{}) // put a componentID/binary mapping to have something in the beats monitoring input
			assert.NoError(t, err)

			rawInputs, ok := got["inputs"]
			require.True(t, ok, "monitoring config contains no input")
			inputs, ok := rawInputs.([]any)
			require.True(t, ok, "monitoring inputs are not a list")
			marshaledInputs, err := yaml.Marshal(inputs)
			if assert.NoError(t, err, "error marshaling monitoring inputs") {
				t.Logf("marshaled monitoring inputs:\n%s\n", marshaledInputs)
			}

			// loop over the created inputs
			for _, i := range inputs {
				input, ok := i.(map[string]any)
				if assert.Truef(t, ok, "input is not represented as a map: %v", i) {
					inputID := input["id"]
					t.Logf("input %q", inputID)
					// check the streams created for the input, should be a list of objects
					if assert.Contains(t, input, "streams", "input %q does not contain any stream", inputID) &&
						assert.IsTypef(t, []any{}, input["streams"], "streams for input %q are not a list of objects", inputID) {

						// loop over streams and cast to map[string]any to access keys
						for _, rawStream := range input["streams"].([]any) {
							if assert.IsTypef(t, map[string]any{}, rawStream, "stream %v for input %q is not a map", rawStream, inputID) {
								stream := rawStream.(map[string]any)
								// check period and assert its value
								streamID := stream["id"]
								if assert.Containsf(t, stream, failureThresholdKey, "stream %q for input %q does not contain a failureThreshold", streamID, inputID) &&
									assert.IsType(t, uint(0), stream[failureThresholdKey], "period for stream %q of input %q is not represented as a string", streamID, inputID) {
									actualFailureThreshold := stream[failureThresholdKey].(uint)
									assert.Equalf(t, actualFailureThreshold, tc.expectedThreshold, "unexpected failure threshold for stream %q of input %q", streamID, inputID)
								}
							}
						}
					}
				}
			}
		})
	}
}

func TestErrorMonitoringConfigMetricsFailureThreshold(t *testing.T) {

	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	components := []component.Component{{ID: "foobeat", InputSpec: &component.InputRuntimeSpec{BinaryName: "filebeat"}}}
	require.NoError(t, err, "Error creating agent info")

	tcs := []struct {
		name          string
		monitoringCfg *monitoringConfig
		policy        map[string]any
		assertError   assert.ErrorAssertionFunc
	}{
		{
			name: "invalid policy failure threshold float64",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: nil,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: float64(-1),
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			assertError: assert.Error,
		},
		{
			name: "invalid policy failure threshold string",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: nil,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: "foobar",
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			assertError: assert.Error,
		},
		{
			name: "invalid policy failure threshold negative number as string",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: nil,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: "-12",
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			assertError: assert.Error,
		},
		{
			name: "invalid policy failure threshold negative int",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					FailureThreshold: nil,
				},
			},
			policy: map[string]any{
				"agent": map[string]any{
					"monitoring": map[string]any{
						"metrics": true,
						"http": map[string]any{
							"enabled": false,
						},
						failureThresholdKey: -12,
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			assertError: assert.Error,
		},
	}

	for _, tc := range tcs {

		t.Run(tc.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled:         true,
				config:          tc.monitoringCfg,
				operatingSystem: runtime.GOOS,
				agentInfo:       agentInfo,
			}

			_, err := b.MonitoringConfig(tc.policy, components, map[string]uint64{}) // put a componentID/binary mapping to have something in the beats monitoring input
			tc.assertError(t, err)
		})
	}
}

func TestMonitoringConfigComponentFields(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	cfg := &monitoringConfig{
		C: &monitoringcfg.MonitoringConfig{
			Enabled:        true,
			MonitorMetrics: true,
			Namespace:      "tiaog",
			HTTP: &monitoringcfg.MonitoringHTTPConfig{
				Enabled: false,
			},
		},
	}

	policy := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"metrics": true,
				"logs":    false,
			},
		},
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	b := &BeatsMonitor{
		enabled:   true,
		config:    cfg,
		agentInfo: agentInfo,
	}

	components := []component.Component{
		{
			ID: "filestream-default",
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Service: &component.ServiceSpec{
						Log: &component.ServiceLogSpec{
							Path: "/tmp/foo",
						},
					},
				},
			},
		},
	}
	monitoringConfig, err := b.MonitoringConfig(policy, components, map[string]uint64{})
	if err != nil {
		t.Fatalf("cannot render monitoring configuration: %s", err)
	}

	// This is a test and the structure of `monitoringConfig` is well know,
	// so we coerce everything to the correct type. If something does not match
	// the test will panic.
	inputsSlice := monitoringConfig["inputs"].([]any)
	for _, input := range inputsSlice {
		inpMap := input.(map[string]any)
		for _, rawStream := range inpMap["streams"].([]any) {
			streamID := rawStream.(map[string]any)["id"].(string)
			processors := rawStream.(map[string]any)["processors"].([]any)
			for _, rawProcessor := range processors {
				processor := rawProcessor.(map[string]any)
				if _, exists := processor["add_fields"]; !exists {
					continue
				}
				streamProc := Processor{}
				if err := json.Unmarshal([]byte(mapstr.M(processor).String()), &streamProc); err != nil {
					t.Errorf("could not decode processor config: %q, err: %s", "foo", err)
				}
				if streamProc.AddFields.Target != "component" {
					continue
				}

				binary := streamProc.AddFields.Fields.Binary
				componentID := streamProc.AddFields.Fields.ID

				// The elastic-Agent is a special case, handle it first
				if strings.Contains(streamID, "monitoring-agent") {
					if binary != "elastic-agent" {
						t.Errorf("expecting fields['binary'] = 'elastic-agent', got %q", binary)
					}
					if componentID != "elastic-agent" {
						t.Errorf("expecting fields['id'] = 'elastic-agent', got %q", componentID)
					}
					continue
				}
				if !strings.Contains(componentID, "monitoring") {
					if binary != "filebeat" {
						t.Errorf("expecting fields['binary'] = 'filebeat', got %q", binary)
					}
					if componentID != "filestream-default" {
						t.Errorf("expecting fields['id'] = 'filestream-default', got %q", componentID)
					}
				} else {
					if binary != "filebeat" && binary != "metricbeat" {
						t.Errorf("expected monitoring compoent to be metricbeat or filebeat, got %s", binary)
					}
					if componentID != monitoringFilesUnitsID && componentID != "beat/metrics-monitoring" && componentID != "http/metrics-monitoring" {
						t.Errorf("got unxpected monitoring component ID: %s", componentID)
					}
				}

			}
		}
	}
}

func TestMonitoringConfigForBeatsReceivers(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	cfg := &monitoringConfig{
		C: &monitoringcfg.MonitoringConfig{
			Enabled:        true,
			MonitorLogs:    true,
			MonitorMetrics: true,
			Namespace:      "test",
			HTTP: &monitoringcfg.MonitoringHTTPConfig{
				Enabled: false,
			},
			RuntimeManager: monitoringcfg.DefaultRuntimeManager,
		},
	}

	policy := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"metrics": true,
				"logs":    false,
			},
		},
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	b := &BeatsMonitor{
		enabled:   true,
		config:    cfg,
		agentInfo: agentInfo,
	}

	components := []component.Component{
		{
			ID: "filestream-process",
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Command: &component.CommandSpec{
						Name: "filebeat",
					},
				},
			},
			RuntimeManager: component.ProcessRuntimeManager,
		},
		{
			ID: "filestream-receiver",
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Command: &component.CommandSpec{
						Name: "filebeat",
					},
				},
			},
			RuntimeManager: component.OtelRuntimeManager,
		},
	}
	monitoringCfgMap, err := b.MonitoringConfig(policy, components, map[string]uint64{})
	require.NoError(t, err)

	// Verify that if we're using filebeat receiver, there's no filebeat input
	var monitoringCfg struct {
		Inputs []struct {
			ID             string
			RuntimeManager string `mapstructure:"_runtime_experimental"`
			Streams        []struct {
				Path string `mapstructure:"path"`
			}
		}
	}
	err = mapstructure.Decode(monitoringCfgMap, &monitoringCfg)
	require.NoError(t, err)
	var streamsForInputMetrics []struct {
		Path string `mapstructure:"path"`
	}
	for _, input := range monitoringCfg.Inputs {
		for _, stream := range input.Streams {
			if stream.Path == "/inputs/" {
				streamsForInputMetrics = append(streamsForInputMetrics, stream)
			}
		}
	}
	assert.Len(t, streamsForInputMetrics, 2)
}

func TestMonitoringWithOtelRuntime(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	cfg := &monitoringConfig{
		C: &monitoringcfg.MonitoringConfig{
			Enabled:        true,
			MonitorLogs:    true,
			MonitorMetrics: true,
			Namespace:      "test",
			HTTP: &monitoringcfg.MonitoringHTTPConfig{
				Enabled: false,
			},
			RuntimeManager: monitoringcfg.OtelRuntimeManager,
		},
	}

	policy := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"metrics": true,
				"logs":    false,
			},
		},
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	b := &BeatsMonitor{
		enabled:   true,
		config:    cfg,
		agentInfo: agentInfo,
	}

	components := []component.Component{
		{
			ID: "filestream-receiver",
			InputSpec: &component.InputRuntimeSpec{
				Spec: component.InputSpec{
					Command: &component.CommandSpec{
						Name: "filebeat",
					},
				},
			},
			RuntimeManager: component.OtelRuntimeManager,
		},
	}
	monitoringCfgMap, err := b.MonitoringConfig(policy, components, map[string]uint64{})
	require.NoError(t, err)

	// Verify that if we're using filebeat receiver, there's no filebeat input
	var monitoringCfg struct {
		Inputs []struct {
			ID             string
			RuntimeManager string `mapstructure:"_runtime_experimental"`
		}
	}
	err = mapstructure.Decode(monitoringCfgMap, &monitoringCfg)
	require.NoError(t, err)
	for _, input := range monitoringCfg.Inputs {
		assert.Equal(t, monitoringcfg.OtelRuntimeManager, input.RuntimeManager)
	}
}

func TestEnrichArgs(t *testing.T) {
	unitID := "test"
	tests := []struct {
		name       string
		enabled    bool
		config     monitoringConfig
		binaryName string
		expected   []string
	}{
		{
			name:       "disabled",
			enabled:    false,
			config:     monitoringConfig{},
			binaryName: "filebeat",
			expected:   nil,
		},
		{
			name:       "unsupported",
			enabled:    true,
			config:     monitoringConfig{},
			binaryName: "unsupported",
			expected:   nil,
		},
		{
			name:       "default",
			enabled:    true,
			config:     monitoringConfig{C: &monitoringcfg.MonitoringConfig{}},
			binaryName: "filebeat",
			expected:   []string{"-E", "http.enabled=true", "-E", "http.host=placeholder", "-E", "logging.metrics.enabled=false"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled: test.enabled,
				config:  &test.config,
			}
			args := b.EnrichArgs(unitID, test.binaryName, nil)
			// replace socket path with placeholder, it's annoying to do cross-platform tests on these
			for i, arg := range args {
				if strings.HasPrefix(arg, "http.host") {
					args[i] = "http.host=placeholder"
				}
			}
			assert.ElementsMatch(t, test.expected, args)
		})
	}
}

type Processor struct {
	AddFields AddFields `json:"add_fields"`
}
type Fields struct {
	Binary string `json:"binary"`
	ID     string `json:"id"`
}
type AddFields struct {
	Fields Fields `json:"fields"`
	Target string `json:"target"`
}

// This test ensures if any field under [agent.monitoring] is unset,
// it falls back to the default value defined in monitoringCfg.DefaultConfig()
func TestMonitorReload(t *testing.T) {
	// set log and metric monitoring to false
	monitorcfg := monitoringcfg.DefaultConfig()
	monitorcfg.MonitorLogs = false
	monitorcfg.MonitorMetrics = false

	beatsMonitor := New(true, "", monitorcfg, nil)
	assert.Equal(t, beatsMonitor.config.C.MonitorLogs, false)
	assert.Equal(t, beatsMonitor.config.C.MonitorLogs, false)

	// unset logs and metrics
	agentConfig := `
agent.monitoring:
  enabled: true
`
	conf := config.MustNewConfigFrom(agentConfig)
	// Reload will set unset fields to default
	err := beatsMonitor.Reload(conf)
	require.NoError(t, err)

	assert.Equal(t, beatsMonitor.config.C.MonitorLogs, true)
	assert.Equal(t, beatsMonitor.config.C.MonitorMetrics, true)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"

	"github.com/elastic/elastic-agent-libs/logp"

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

	policy := map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{
				"hosts": []string{"localhost:9200"},
				"type":  "elasticsearch",
			},
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

	testCases := []struct {
		Name               string
		RuntimeManager     string
		ExpectedConfigPath string
	}{
		{
			Name:               "Default runtime manager",
			RuntimeManager:     monitoringcfg.DefaultRuntimeManager,
			ExpectedConfigPath: filepath.Join(".", "testdata", "monitoring_config_full_otel.yaml"),
		},
		{
			Name:               "Process runtime manager",
			RuntimeManager:     monitoringcfg.ProcessRuntimeManager,
			ExpectedConfigPath: filepath.Join(".", "testdata", "monitoring_config_full_process.yaml"),
		},
		{
			Name:               "Otel runtime manager",
			RuntimeManager:     monitoringcfg.OtelRuntimeManager,
			ExpectedConfigPath: filepath.Join(".", "testdata", "monitoring_config_full_otel.yaml"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			monitoringCfg := &monitoringConfig{
				C: monitoringcfg.DefaultConfig(),
			}
			monitoringCfg.C.RuntimeManager = tc.RuntimeManager
			testMon := BeatsMonitor{
				enabled:   true,
				config:    monitoringCfg,
				agentInfo: agentInfo,
				logger:    logp.NewNopLogger(),
			}

			expectedConfigBytes, err := os.ReadFile(tc.ExpectedConfigPath)
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
		})
	}
}

func TestMonitoringWithEndpoint(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	testMon := BeatsMonitor{
		enabled: true,
		config: &monitoringConfig{
			C: monitoringcfg.DefaultConfig(),
		},
		agentInfo: agentInfo,
		logger:    logp.NewNopLogger(),
	}

	policy := map[string]any{
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
	defaultConfigWithoutLogs := monitoringcfg.DefaultConfig()
	defaultConfigWithoutLogs.MonitorLogs = false

	tcs := []struct {
		name             string
		monitoringCfg    *monitoringConfig
		policy           map[string]any
		expectedInterval time.Duration
	}{
		{
			name: "default metrics interval",
			monitoringCfg: &monitoringConfig{
				C: defaultConfigWithoutLogs,
			},
			policy: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedInterval: monitoringcfg.DefaultMetricsCollectionInterval,
		},
		{
			name: "agent config metrics interval",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: true,
					},
					UseOutput:     monitoringcfg.DefaultOutputName,
					MetricsPeriod: time.Second * 20,
				},
			},
			policy: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedInterval: 20 * time.Second,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled:         true,
				config:          tc.monitoringCfg,
				operatingSystem: runtime.GOOS,
				agentInfo:       agentInfo,
				logger:          logp.NewNopLogger(),
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
	defaultConfigWithoutLogs := monitoringcfg.DefaultConfig()
	defaultConfigWithoutLogs.MonitorLogs = false
	sampleSevenErrorsStreamThreshold := uint(7)

	tcs := []struct {
		name              string
		monitoringCfg     *monitoringConfig
		policy            map[string]any
		expectedThreshold uint
	}{
		{
			name: "default failure threshold",
			monitoringCfg: &monitoringConfig{
				C: defaultConfigWithoutLogs,
			},
			policy: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: monitoringcfg.DefaultMetricsStreamFailureThreshold,
		},
		{
			name: "agent config failure threshold",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: true,
					},
					UseOutput:        monitoringcfg.DefaultOutputName,
					FailureThreshold: &sampleSevenErrorsStreamThreshold,
				},
			},
			policy: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{},
				},
			},
			expectedThreshold: sampleSevenErrorsStreamThreshold,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled:         true,
				config:          tc.monitoringCfg,
				operatingSystem: runtime.GOOS,
				agentInfo:       agentInfo,
				logger:          logp.NewNopLogger(),
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

func TestMonitoringConfigComponentFields(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	cfg := &monitoringConfig{
		C: &monitoringcfg.MonitoringConfig{
			Enabled:        true,
			MonitorMetrics: true,
			HTTP: &monitoringcfg.MonitoringHTTPConfig{
				Enabled: false,
			},
			UseOutput: monitoringcfg.DefaultOutputName,
		},
	}

	policy := map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	b := &BeatsMonitor{
		enabled:   true,
		config:    cfg,
		agentInfo: agentInfo,
		logger:    logp.NewNopLogger(),
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
			UseOutput:      monitoringcfg.DefaultOutputName,
		},
	}

	policy := map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}

	b := &BeatsMonitor{
		enabled:   true,
		config:    cfg,
		agentInfo: agentInfo,
		logger:    logp.NewNopLogger(),
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
	assert.Len(t, streamsForInputMetrics, 3)
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
			UseOutput:      monitoringcfg.DefaultOutputName,
		},
	}

	policy := map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{
				"hosts": []string{"localhost:9200"},
				"type":  "elasticsearch",
			},
		},
	}

	b := &BeatsMonitor{
		enabled:   true,
		config:    cfg,
		agentInfo: agentInfo,
		logger:    logp.NewNopLogger(),
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
			Streams        []struct {
				ID string `mapstructure:"id"`
			} `mapstructure:"streams"`
		}
	}
	err = mapstructure.Decode(monitoringCfgMap, &monitoringCfg)
	require.NoError(t, err)
	edotSubprocessStreamID := fmt.Sprintf("%s-edot-collector", monitoringMetricsUnitID)
	foundEdotSubprocessStream := false
	for _, input := range monitoringCfg.Inputs {
		assert.Equal(t, monitoringcfg.OtelRuntimeManager, input.RuntimeManager)
		if !foundEdotSubprocessStream && input.ID == "metrics-monitoring-agent" {
			for _, stream := range input.Streams {
				if stream.ID == edotSubprocessStreamID {
					foundEdotSubprocessStream = true
					break
				}
			}
		}
	}
	require.True(t, foundEdotSubprocessStream, "edot subprocess stream not found")
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
				logger:  logp.NewNopLogger(),
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

	beatsMonitor := New(true, "", monitorcfg, nil, logp.NewNopLogger())
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

func TestMonitoringConfigOtelOutputSupport(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	testCases := []struct {
		name                       string
		outputConfig               map[string]any
		expectPrometheusMonitoring bool
		monitoringRuntimeManager   string
	}{
		{
			name: "kafka output - should NOT have prometheus monitoring",
			outputConfig: map[string]any{
				"type":  "kafka",
				"hosts": []string{"localhost:9092"},
			},
			expectPrometheusMonitoring: false,
			monitoringRuntimeManager:   monitoringcfg.ProcessRuntimeManager,
		},
		{
			name: "logstash output - should NOT have prometheus monitoring",
			outputConfig: map[string]any{
				"type":  "logstash",
				"hosts": []string{"localhost:9092"},
			},
			expectPrometheusMonitoring: false,
			monitoringRuntimeManager:   monitoringcfg.ProcessRuntimeManager,
		},
		{
			name: "elasticsearch output - should have prometheus monitoring",
			outputConfig: map[string]any{
				"type":  "elasticsearch",
				"hosts": []string{"localhost:9200"},
			},
			expectPrometheusMonitoring: true,
			monitoringRuntimeManager:   monitoringcfg.OtelRuntimeManager,
		},
		{
			name: "elasticsearch with unsupported config - should NOT have prometheus monitoring",
			outputConfig: map[string]any{
				"type":    "elasticsearch",
				"hosts":   []string{"localhost:9200"},
				"indices": []any{},
			},
			expectPrometheusMonitoring: false,
			monitoringRuntimeManager:   monitoringcfg.ProcessRuntimeManager,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testMon := BeatsMonitor{
				enabled: true,
				config: &monitoringConfig{
					C: &monitoringcfg.MonitoringConfig{
						Enabled:        true,
						MonitorMetrics: true,
						MonitorLogs:    false,
						HTTP: &monitoringcfg.MonitoringHTTPConfig{
							Enabled: false,
						},
						RuntimeManager: monitoringcfg.OtelRuntimeManager,
						UseOutput:      monitoringcfg.DefaultOutputName,
					},
				},
				agentInfo: agentInfo,
				logger:    logp.NewNopLogger(),
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
					"default": tc.outputConfig,
				},
			}

			// Add a component that uses the OTel runtime to trigger prometheus monitoring
			components := []component.Component{
				{
					ID: "filestream-otel",
					InputSpec: &component.InputRuntimeSpec{
						BinaryName: "filebeat",
						Spec: component.InputSpec{
							Command: &component.CommandSpec{
								Name: "filebeat",
							},
						},
					},
					RuntimeManager: component.OtelRuntimeManager,
				},
			}

			outCfg, err := testMon.MonitoringConfig(policy, components, map[string]uint64{})
			require.NoError(t, err)

			// Check for prometheus/metrics input
			inputs := outCfg["inputs"].([]any)
			foundPrometheusInput := false
			for _, input := range inputs {
				var inputStruct struct {
					ID      string `mapstructure:"id"`
					Type    string `mapstructure:"type"`
					Runtime string `mapstructure:"_runtime_experimental"`
				}
				require.NoError(t, mapstructure.Decode(input, &inputStruct))
				foundPrometheusInput = foundPrometheusInput || inputStruct.Type == "prometheus/metrics"
				assert.Equalf(t, tc.monitoringRuntimeManager, inputStruct.Runtime,
					"expected monitoring runtime manager %s for input %s, got %s",
					tc.monitoringRuntimeManager, inputStruct.ID, inputStruct.Runtime)
			}

			assert.Equal(t, tc.expectPrometheusMonitoring, foundPrometheusInput,
				"Prometheus monitoring presence mismatch for output type")
		})
	}
}

func TestMonitoringConfigParameterParsing(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")
	components := []component.Component{{ID: "foobeat", InputSpec: &component.InputRuntimeSpec{BinaryName: "filebeat"}}}
	failureThreshold := uint(15)

	tcs := []struct {
		name           string
		monitoringCfg  *monitoringConfig
		policy         map[string]any
		expectedOutput map[string]any
	}{
		{
			name: "default values",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					UseOutput: monitoringcfg.DefaultOutputName,
				},
			},
			policy: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type":  "elasticsearch",
						"hosts": []string{"http://localhost:9200"},
					},
				},
			},
			expectedOutput: map[string]any{
				"type":  "elasticsearch",
				"hosts": []string{"http://localhost:9200"},
			},
		},
		{
			name: "custom values",
			monitoringCfg: &monitoringConfig{
				C: &monitoringcfg.MonitoringConfig{
					Enabled:        true,
					MonitorMetrics: true,
					HTTP: &monitoringcfg.MonitoringHTTPConfig{
						Enabled: false,
					},
					MetricsPeriod:    time.Second * 30,
					FailureThreshold: &failureThreshold,
					UseOutput:        "custom",
				},
			},
			policy: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type":  "elasticsearch",
						"hosts": []string{"http://localhost:9200"},
					},
					"custom": map[string]any{
						"type":  "logstash",
						"hosts": []string{"http://localhost:5044"},
					},
				},
			},
			expectedOutput: map[string]any{
				"type":  "logstash",
				"hosts": []string{"http://localhost:5044"},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b := &BeatsMonitor{
				enabled:         true,
				config:          tc.monitoringCfg,
				operatingSystem: runtime.GOOS,
				agentInfo:       agentInfo,
				logger:          logp.NewNopLogger(),
			}
			got, err := b.MonitoringConfig(tc.policy, components, map[string]uint64{})
			assert.NoError(t, err)

			// Check output
			rawOutputs, ok := got["outputs"]
			require.True(t, ok, "monitoring config contains no outputs")
			outputs, ok := rawOutputs.(map[string]any)
			require.True(t, ok, "monitoring outputs are not a map")

			monitoringOutput, ok := outputs["monitoring"]
			require.True(t, ok, "no 'monitoring' output found")
			assert.Equal(t, tc.expectedOutput, monitoringOutput)

			// Check interval and threshold
			rawInputs, ok := got["inputs"]
			require.True(t, ok, "monitoring config contains no input")
			inputs, ok := rawInputs.([]any)
			require.True(t, ok, "monitoring inputs are not a list")

			for _, i := range inputs {
				input, ok := i.(map[string]any)
				if !assert.Truef(t, ok, "input is not represented as a map: %v", i) {
					continue
				}

				if input["type"] == "filestream" {
					continue // filestream inputs don't have these params
				}

				inputID := input["id"]
				if !assert.Contains(t, input, "streams", "input %q does not contain any stream", inputID) {
					continue
				}
				if !assert.IsTypef(t, []any{}, input["streams"], "streams for input %q are not a list of objects", inputID) {
					continue
				}
			}
		})
	}
}

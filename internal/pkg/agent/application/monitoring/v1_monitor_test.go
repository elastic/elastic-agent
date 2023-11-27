// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	monitoringcfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestMonitoringConfigMetricsInterval(t *testing.T) {

	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	mCfg := &monitoringConfig{
		C: &monitoringcfg.MonitoringConfig{
			Enabled:        true,
			MonitorMetrics: true,
			HTTP: &monitoringcfg.MonitoringHTTPConfig{
				Enabled: false,
			},
		},
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
	b := &BeatsMonitor{
		enabled:         true,
		config:          mCfg,
		operatingSystem: runtime.GOOS,
		agentInfo:       agentInfo,
	}
	got, err := b.MonitoringConfig(policy, nil, map[string]string{"foobeat": "filebeat"}) // put a componentID/binary mapping to have something in the beats monitoring input
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
						if assert.Containsf(t, stream, "period", "stream %q for input %q does not contain a period", streamID, inputID) &&
							assert.IsType(t, "", stream["period"], "period for stream %q of input %q is not represented as a string", streamID, inputID) {
							periodString := stream["period"].(string)
							duration, err := time.ParseDuration(periodString)
							if assert.NoErrorf(t, err, "Unparseable period duration %s for stream %q of input %q", periodString, streamID, inputID) {
								assert.Equalf(t, duration, 60*time.Second, "unexpected duration for stream %q of input %q", streamID, inputID)
							}
						}
					}
				}
			}
		}

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
	monitoringConfig, err := b.MonitoringConfig(policy, components, map[string]string{"filestream-default": "filebeat"})
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
				p := Processor{}
				if err := json.Unmarshal([]byte(mapstr.M(processor).String()), &p); err != nil {
					t.Errorf("could not decode processor config: %q, err: %s", "foo", err)
				}
				if p.AddFields.Target != "component" {
					continue
				}

				binary := p.AddFields.Fields.Binary
				componentID := p.AddFields.Fields.ID

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
				if binary != "filebeat" {
					t.Errorf("expecting fields['binary'] = 'filebeat', got %q", binary)
				}
				if componentID != "filestream-default" {
					t.Errorf("expecting fields['id'] = 'filestream-default', got %q", componentID)
				}

			}
		}
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

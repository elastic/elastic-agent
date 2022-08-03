// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

func TestToComponents(t *testing.T) {
	var linuxAMD64Platform = PlatformDetail{
		Platform: Platform{
			OS:   Linux,
			Arch: AMD64,
			GOOS: Linux,
		},
	}

	scenarios := []struct {
		Name     string
		Platform PlatformDetail
		Policy   map[string]interface{}
		Err      string
		Result   []Component
	}{
		{
			Name:     "Empty policy",
			Platform: linuxAMD64Platform,
			Policy:   map[string]interface{}{},
		},
		{
			Name:     "Invalid: outputs as an array",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": []string{"should be a map"},
			},
			Err: "invalid 'outputs', expected a map not a []string",
		},
		{
			Name:     "Invalid: outputs entry as an array",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": []string{"should be a map"},
				},
			},
			Err: "invalid 'outputs.default', expected a map not a []string",
		},
		{
			Name:     "Invalid: outputs entry missing type",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{},
				},
			},
			Err: "invalid 'outputs.default', 'type' missing",
		},
		{
			Name:     "Invalid: outputs entry type not a string",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type": 0,
					},
				},
			},
			Err: "invalid 'outputs.default.type', expected a string not a int",
		},
		{
			Name:     "Invalid: outputs entry type not a string",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": "false",
					},
				},
			},
			Err: "invalid 'outputs.default.enabled', expected a bool not a string",
		},
		{
			Name:     "No inputs",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
			},
		},
		{
			Name:     "Invalid: inputs as a map",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": map[string]interface{}{},
			},
			Err: "invalid 'inputs', expected an array not a map[string]interface {}",
		},
		{
			Name:     "Invalid: inputs entry as an array",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					[]string{"should be a map"},
				},
			},
			Err: "invalid 'inputs.0', expected a map not a []string",
		},
		{
			Name:     "Invalid: inputs entry missing type",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{},
				},
			},
			Err: "invalid 'inputs.0', 'type' missing",
		},
		{
			Name:     "Invalid: inputs entry type not a string",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type": 0,
					},
				},
			},
			Err: "invalid 'inputs.0.type', expected a string not a int",
		},
		{
			Name:     "Invalid: inputs entry missing id",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type": "filestream",
					},
				},
			},
			Err: "invalid 'inputs.0', 'id' missing",
		},
		{
			Name:     "Invalid: inputs entry id not a string",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type": "filestream",
						"id":   0,
					},
				},
			},
			Err: "invalid 'inputs.0.id', expected a string not a int",
		},
		{
			Name:     "Invalid: inputs entry use_output not a string",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-0",
						"use_output": 0,
					},
				},
			},
			Err: "invalid 'inputs.0.use_output', expected a string not a int",
		},
		{
			Name:     "Invalid: inputs entry use_output references unknown output",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-0",
						"use_output": "other",
					},
				},
			},
			Err: "invalid 'inputs.0.use_output', references an unknown output 'other'",
		},
		{
			Name:     "Invalid: inputs entry enabled not a bool",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-0",
						"use_output": "default",
						"enabled":    "false",
					},
				},
			},
			Err: "invalid 'inputs.0.enabled', expected a bool not a string",
		},
		{
			Name:     "Invalid: inputs unknown type",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "unknown",
						"id":         "unknown-0",
						"use_output": "default",
						"enabled":    true,
					},
				},
			},
			Result: []Component{
				{
					ID:   "unknown-default",
					Spec: InputRuntimeSpec{},
					Err:  ErrInputNotSupported,
					Units: []Unit{
						{
							ID:   "unknown-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "unknown-default-unknown-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "unknown",
								"id":   "unknown-0",
							}),
						},
					},
				},
			},
		},
		{
			Name: "Invalid: inputs endpoint not support on container platform",
			Platform: PlatformDetail{
				Platform: Platform{
					OS:   Container,
					Arch: AMD64,
					GOOS: Linux,
				},
			},
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "endpoint",
						"id":         "endpoint-0",
						"use_output": "default",
						"enabled":    true,
					},
				},
			},
			Result: []Component{
				{
					ID:   "endpoint-default",
					Spec: InputRuntimeSpec{},
					Err:  ErrInputNotSupportedOnPlatform,
					Units: []Unit{
						{
							ID:   "endpoint-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "endpoint-default-endpoint-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "endpoint",
								"id":   "endpoint-0",
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Invalid: inputs endpoint doesn't support logstash",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type": "logstash",
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type": "endpoint",
						"id":   "endpoint-0",
					},
				},
			},
			Result: []Component{
				{
					ID:   "endpoint-default",
					Spec: InputRuntimeSpec{},
					Err:  ErrOutputNotSupported,
					Units: []Unit{
						{
							ID:   "endpoint-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:   "endpoint-default-endpoint-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "endpoint",
								"id":   "endpoint-0",
							}),
						},
					},
				},
			},
		},
		{
			Name: "Invalid: inputs endpoint doesnt support arm64 redhat major 7",
			Platform: PlatformDetail{
				Platform: Platform{
					OS:   Linux,
					Arch: ARM64,
					GOOS: Linux,
				},
				Family: "redhat",
				Major:  "7",
				Minor:  "2",
			},
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "endpoint",
						"id":         "endpoint-0",
						"use_output": "default",
						"enabled":    true,
					},
				},
			},
			Result: []Component{
				{
					ID:   "endpoint-default",
					Spec: InputRuntimeSpec{},
					Err:  NewErrInputRuntimeCheckFail("No support for RHEL7 on arm64"),
					Units: []Unit{
						{
							ID:   "endpoint-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "endpoint-default-endpoint-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "endpoint",
								"id":   "endpoint-0",
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Invalid: single input failed to decode into config",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-0",
						"use_output": "default",
						"enabled":    true,
					},
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-1",
						"use_output": "default",
						"enabled":    true,
						"meta": []interface{}{
							map[string]interface{}{
								"bad": "should not have been array of dicts",
							},
						},
					},
				},
			},
			Result: []Component{
				{
					ID: "filestream-default",
					Spec: InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "filestream-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "filestream-default-filestream-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
						{
							ID:   "filestream-default-filestream-1",
							Type: client.UnitTypeInput,
							Err:  errors.New("1 decoding error(s): 'meta' expected a map, got 'slice'"),
						},
					},
				},
			},
		},
		{
			Name:     "Output disabled",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": false,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":    "filestream",
						"id":      "filestream-0",
						"enabled": true,
					},
				},
			},
		},
		{
			Name:     "Input disabled",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":    "filestream",
						"id":      "filestream-0",
						"enabled": false,
					},
				},
			},
		},
		{
			Name:     "Simple representation",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":    "filestream",
						"id":      "filestream-0",
						"enabled": true,
					},
					map[string]interface{}{
						"type":    "filestream",
						"id":      "filestream-1",
						"enabled": false,
					},
				},
			},
			Result: []Component{
				{
					Spec: InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "filestream-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "filestream-default-filestream-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Complex representation",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type": "elasticsearch",
					},
					"other": map[string]interface{}{
						"type": "elasticsearch",
					},
					"stashit": map[string]interface{}{
						"type": "logstash",
					},
					"redis": map[string]interface{}{
						"type": "redis",
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type": "filestream",
						"id":   "filestream-0",
					},
					map[string]interface{}{
						"type": "filestream",
						"id":   "filestream-1",
					},
					map[string]interface{}{
						"type":    "filestream",
						"id":      "filestream-2",
						"enabled": false,
					},
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-3",
						"use_output": "other",
					},
					map[string]interface{}{
						"type":       "filestream",
						"id":         "filestream-4",
						"use_output": "other",
					},
					map[string]interface{}{
						"type":       "logfile",
						"id":         "logfile-0",
						"use_output": "default",
					},
					map[string]interface{}{
						"type":       "log",
						"id":         "logfile-1",
						"use_output": "default",
					},
					map[string]interface{}{
						"type":       "logfile",
						"id":         "logfile-2",
						"use_output": "other",
					},
					map[string]interface{}{
						"type":       "logfile",
						"id":         "logfile-3",
						"use_output": "stashit",
					},
					map[string]interface{}{
						"type":       "logfile",
						"id":         "logfile-4",
						"use_output": "redis",
					},
					map[string]interface{}{
						"type": "apm",
						"id":   "apm-server-0",
					},
				},
			},
			Result: []Component{
				{
					Spec: InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "filestream-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "filestream-default-filestream-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
						{
							ID:   "filestream-default-filestream-1",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-1",
							}),
						},
					},
				},
				{
					Spec: InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "filestream-other",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "filestream-other-filestream-3",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-3",
							}),
						},
						{
							ID:   "filestream-other-filestream-4",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-4",
							}),
						},
					},
				},
				{
					Spec: InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "log-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "log-default-logfile-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logfile",
								"id":   "logfile-0",
							}),
						},
						{
							ID:   "log-default-logfile-1",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "log",
								"id":   "logfile-1",
							}),
						},
					},
				},
				{
					Spec: InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "log-other",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "log-other-logfile-2",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logfile",
								"id":   "logfile-2",
							}),
						},
					},
				},
				{
					Spec: InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "log-stashit",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:   "log-stashit-logfile-3",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logfile",
								"id":   "logfile-3",
							}),
						},
					},
				},
				{
					Spec: InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:   "log-redis",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "redis",
							}),
						},
						{
							ID:   "log-redis-logfile-4",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logfile",
								"id":   "logfile-4",
							}),
						},
					},
				},
				{
					Spec: InputRuntimeSpec{
						InputType:  "apm",
						BinaryName: "apm-server",
						BinaryPath: filepath.Join("..", "..", "specs", "apm-server"),
					},
					Units: []Unit{
						{
							ID:   "apm-default",
							Type: client.UnitTypeOutput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:   "apm-default-apm-server-0",
							Type: client.UnitTypeInput,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "apm",
								"id":   "apm-server-0",
							}),
						},
					},
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			runtime, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), scenario.Platform, SkipBinaryCheck())
			require.NoError(t, err)

			result, err := runtime.ToComponents(scenario.Policy)
			if scenario.Err != "" {
				assert.Equal(t, scenario.Err, err.Error())
			} else {
				require.NoError(t, err)
				require.Len(t, result, len(scenario.Result))
				sortComponents(scenario.Result)
				sortComponents(result)
				for i, expected := range scenario.Result {
					actual := result[i]
					if expected.Err != nil {
						assert.Equal(t, expected.Err, actual.Err)
						assert.EqualValues(t, expected.Units, actual.Units)
					} else {
						assert.Equal(t, expected.Spec.InputType, actual.Spec.InputType)
						assert.Equal(t, expected.Spec.BinaryName, actual.Spec.BinaryName)
						assert.Equal(t, expected.Spec.BinaryPath, actual.Spec.BinaryPath)
						assert.EqualValues(t, expected.Units, actual.Units)
					}
				}
			}
		})
	}
}

func sortComponents(components []Component) {
	for _, comp := range components {
		sort.Slice(comp.Units, func(i, j int) bool {
			return comp.Units[i].ID < comp.Units[j].ID
		})
	}
	sort.Slice(components[:], func(i, j int) bool {
		return components[i].Units[0].ID < components[j].Units[0].ID
	})
}

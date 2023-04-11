// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package component

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
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
		LogLevel logp.Level
		Err      string
		Result   []Component
		headers  HeadersProvider
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
			Name:     "Invalid: inputs entry duplicate because of missing id",
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
					map[string]interface{}{
						"type": "filestream",
					},
				},
			},
			Err: `invalid 'inputs.1.id', has a duplicate id "filestream". Please add a unique value for the 'id' key to each input in the agent policy`,
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
					ID:        "unknown-default",
					InputSpec: &InputRuntimeSpec{},
					Err:       ErrInputNotSupported,
					Units: []Unit{
						{
							ID:       "unknown-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "unknown-default-unknown-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
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
						"type": "fleet-server",
						"id":   "fleet-server-0",
					},
				},
			},
			Result: []Component{
				{
					ID:        "fleet-server-default",
					InputSpec: &InputRuntimeSpec{},
					Err:       ErrOutputNotSupported,
					Units: []Unit{
						{
							ID:       "fleet-server-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:       "fleet-server-default-fleet-server-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "fleet-server",
								"id":   "fleet-server-0",
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
					ID:        "endpoint-default",
					InputSpec: &InputRuntimeSpec{},
					Err:       NewErrInputRuntimeCheckFail("No support for RHEL7 on arm64"),
					Units: []Unit{
						{
							ID:       "endpoint-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "endpoint-default-endpoint-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
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
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
						{
							ID:       "filestream-default-filestream-1",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Err:      errors.New("1 decoding error(s): 'meta' expected a map, got 'slice'"),
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
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
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
			Name:     "Debug log level",
			Platform: linuxAMD64Platform,
			LogLevel: logp.DebugLevel,
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
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: client.UnitLogLevelDebug,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: client.UnitLogLevelDebug,
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
			Name:     "Unique log level",
			Platform: linuxAMD64Platform,
			LogLevel: logp.ErrorLevel,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":      "filestream",
						"id":        "filestream-0",
						"enabled":   true,
						"log_level": "debug",
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
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: client.UnitLogLevelError,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: client.UnitLogLevelDebug,
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
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
						{
							ID:       "filestream-default-filestream-1",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-1",
							}),
						},
					},
				},
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-other",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "filestream-other-filestream-3",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-3",
							}),
						},
						{
							ID:       "filestream-other-filestream-4",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-4",
							}),
						},
					},
				},
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "log-default-logfile-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-0",
							}, "log"),
						},
						{
							ID:       "log-default-logfile-1",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "log",
								"id":   "logfile-1",
							}),
						},
					},
				},
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-other",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "log-other-logfile-2",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-2",
							}, "log"),
						},
					},
				},
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-stashit",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:       "log-stashit-logfile-3",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-3",
							}, "log"),
						},
					},
				},
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-redis",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "redis",
							}),
						},
						{
							ID:       "log-redis-logfile-4",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-4",
							}, "log"),
						},
					},
				},
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "apm",
						BinaryName: "apm-server",
						BinaryPath: filepath.Join("..", "..", "specs", "apm-server"),
					},
					Units: []Unit{
						{
							ID:       "apm-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "apm-default-apm-server-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "apm",
								"id":   "apm-server-0",
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Simple w/ shipper",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
						"shipper": map[string]interface{}{
							"enabled": true,
						},
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
					ID: "filestream-default",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "shipper",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
					},
					Shipper: &ShipperReference{
						ComponentID: "shipper-default",
						UnitID:      "filestream-default",
					},
				},
				{
					ID: "shipper-default",
					ShipperSpec: &ShipperRuntimeSpec{
						ShipperType: "shipper",
						BinaryName:  "shipper",
						BinaryPath:  filepath.Join("..", "..", "specs", "shipper"),
					},
					Units: []Unit{
						{
							ID:       "shipper-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"shipper": map[string]interface{}{
									"enabled": true,
								},
							}),
						},
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"id":   "filestream-default",
								"type": "shipper",
								"units": []interface{}{
									map[string]interface{}{
										"id": "filestream-default-filestream-0",
										"config": map[string]interface{}{
											"type": "filestream",
											"id":   "filestream-0",
										},
									},
								},
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Complex w/ shipper",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"shipper": map[string]interface{}{},
					},
					"other": map[string]interface{}{
						"type": "elasticsearch",
						"shipper": map[string]interface{}{
							"enabled": false,
						},
					},
					"stashit": map[string]interface{}{
						"type":    "logstash",
						"shipper": map[string]interface{}{},
					},
					"redis": map[string]interface{}{
						"type":    "redis",
						"shipper": map[string]interface{}{},
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
					ID: "filestream-default",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "shipper",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
						{
							ID:       "filestream-default-filestream-1",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-1",
							}),
						},
					},
					Shipper: &ShipperReference{
						ComponentID: "shipper-default",
						UnitID:      "filestream-default",
					},
				},
				{
					ID: "filestream-other",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-other",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"shipper": map[string]interface{}{
									"enabled": false,
								},
							}),
						},
						{
							ID:       "filestream-other-filestream-3",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-3",
							}),
						},
						{
							ID:       "filestream-other-filestream-4",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-4",
							}),
						},
					},
				},
				{
					ID: "log-default",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "shipper",
							}),
						},
						{
							ID:       "log-default-logfile-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-0",
							}, "log"),
						},
						{
							ID:       "log-default-logfile-1",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "log",
								"id":   "logfile-1",
							}),
						},
					},
					Shipper: &ShipperReference{
						ComponentID: "shipper-default",
						UnitID:      "log-default",
					},
				},
				{
					ID: "shipper-default",
					ShipperSpec: &ShipperRuntimeSpec{
						ShipperType: "shipper",
						BinaryName:  "shipper",
						BinaryPath:  filepath.Join("..", "..", "specs", "shipper"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"id":   "filestream-default",
								"type": "shipper",
								"units": []interface{}{
									map[string]interface{}{
										"id": "filestream-default-filestream-0",
										"config": map[string]interface{}{
											"type": "filestream",
											"id":   "filestream-0",
										},
									},
									map[string]interface{}{
										"id": "filestream-default-filestream-1",
										"config": map[string]interface{}{
											"type": "filestream",
											"id":   "filestream-1",
										},
									},
								},
							}),
						},
						{
							ID:       "log-default",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"id":   "log-default",
								"type": "shipper",
								"units": []interface{}{
									map[string]interface{}{
										"id": "log-default-logfile-0",
										"config": map[string]interface{}{
											"type": "log",
											"id":   "logfile-0",
										},
									},
									map[string]interface{}{
										"id": "log-default-logfile-1",
										"config": map[string]interface{}{
											"type": "log",
											"id":   "logfile-1",
										},
									},
								},
							}),
						},
						{
							ID:       "shipper-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type":    "elasticsearch",
								"shipper": map[string]interface{}{},
							}),
						},
					},
				},
				{
					ID: "log-other",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-other",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"shipper": map[string]interface{}{
									"enabled": false,
								},
							}),
						},
						{
							ID:       "log-other-logfile-2",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-2",
							}, "log"),
						},
					},
				},
				{
					ID: "log-stashit",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-stashit",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "shipper",
							}),
						},
						{
							ID:       "log-stashit-logfile-3",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-3",
							}, "log"),
						},
					},
					Shipper: &ShipperReference{
						ComponentID: "shipper-stashit",
						UnitID:      "log-stashit",
					},
				},
				{
					ID: "shipper-stashit",
					ShipperSpec: &ShipperRuntimeSpec{
						ShipperType: "shipper",
						BinaryName:  "shipper",
						BinaryPath:  filepath.Join("..", "..", "specs", "shipper"),
					},
					Units: []Unit{
						{
							ID:       "log-stashit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"id":   "log-stashit",
								"type": "shipper",
								"units": []interface{}{
									map[string]interface{}{
										"id": "log-stashit-logfile-3",
										"config": map[string]interface{}{
											"type": "log",
											"id":   "logfile-3",
										},
									},
								},
							}),
						},
						{
							ID:       "shipper-stashit",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type":    "logstash",
								"shipper": map[string]interface{}{},
							}),
						},
					},
				},
				{
					ID: "log-redis",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-redis",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "shipper",
							}),
						},
						{
							ID:       "log-redis-logfile-4",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "log",
								"id":   "logfile-4",
							}, "log"),
						},
					},
					Shipper: &ShipperReference{
						ComponentID: "shipper-redis",
						UnitID:      "log-redis",
					},
				},
				{
					ID: "shipper-redis",
					ShipperSpec: &ShipperRuntimeSpec{
						ShipperType: "shipper",
						BinaryName:  "shipper",
						BinaryPath:  filepath.Join("..", "..", "specs", "shipper"),
					},
					Units: []Unit{
						{
							ID:       "log-redis",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"id":   "log-redis",
								"type": "shipper",
								"units": []interface{}{
									map[string]interface{}{
										"id": "log-redis-logfile-4",
										"config": map[string]interface{}{
											"type": "log",
											"id":   "logfile-4",
										},
									},
								},
							}),
						},
						{
							ID:       "shipper-redis",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type":    "redis",
								"shipper": map[string]interface{}{},
							}),
						},
					},
				},
				{
					ID: "apm-default",
					InputSpec: &InputRuntimeSpec{
						InputType:  "apm",
						BinaryName: "apm-server",
						BinaryPath: filepath.Join("..", "..", "specs", "apm-server"),
					},
					Units: []Unit{
						{
							ID:       "apm-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type":    "elasticsearch",
								"shipper": map[string]interface{}{},
							}),
						},
						{
							ID:       "apm-default-apm-server-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "apm",
								"id":   "apm-server-0",
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Alias representation",
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
						"type":    "logfile",
						"id":      "some-id",
						"enabled": true,
					},
					map[string]interface{}{
						"type":    "log",
						"id":      "log-1",
						"enabled": true,
					},
				},
			},
			Result: []Component{
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "log-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "log-default-some-id",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "log",
								"id":   "some-id",
							}),
						},
						{
							ID:       "log-default-log-1",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "log",
								"id":   "log-1",
							}),
						},
					},
				},
			},
		},
		{
			Name:     "Headers injection",
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
				},
			},
			Result: []Component{
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"headers": map[string]interface{}{
									"header-one": "val-1",
								},
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"header-one": "val-1",
			}},
		}, {
			Name:     "Headers injection merge",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
						"headers": map[string]interface{}{
							"header-two": "val-2",
						},
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
			Result: []Component{
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"headers": map[string]interface{}{
									"header-two": "val-2",
									"header-one": "val-1",
								},
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"header-one": "val-1",
			}},
		},
		{
			Name:     "Headers injection not injecting kafka",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "kafka",
						"enabled": true,
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
			Result: []Component{
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "kafka",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"header-one": "val-1",
			}},
		},
		{
			Name:     "Headers injection not injecting logstash",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "logstash",
						"enabled": true,
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
			Result: []Component{
				{
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "filebeat",
						BinaryPath: filepath.Join("..", "..", "specs", "filebeat"),
					},
					Units: []Unit{
						{
							ID:       "filestream-default",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:       "filestream-default-filestream-0",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "filestream",
								"id":   "filestream-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"header-one": "val-1",
			}},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			runtime, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), scenario.Platform, SkipBinaryCheck())
			require.NoError(t, err)

			result, err := runtime.ToComponents(scenario.Policy, nil, scenario.LogLevel, scenario.headers)
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
					} else if expected.InputSpec != nil {
						assert.Nil(t, actual.ShipperSpec)
						assert.Equal(t, expected.InputSpec.InputType, actual.InputSpec.InputType)
						assert.Equal(t, expected.InputSpec.BinaryName, actual.InputSpec.BinaryName)
						assert.Equal(t, expected.InputSpec.BinaryPath, actual.InputSpec.BinaryPath)
						for i, eu := range expected.Units {
							assert.EqualValues(t, eu.Config, actual.Units[i].Config)
						}
						assert.EqualValues(t, expected.Units, actual.Units)
						if expected.Shipper != nil {
							assert.Equal(t, *expected.Shipper, *actual.Shipper)
						} else {
							assert.Nil(t, actual.Shipper)
						}
					} else if expected.ShipperSpec != nil {
						assert.Nil(t, actual.InputSpec)
						assert.Equal(t, expected.ShipperSpec.ShipperType, actual.ShipperSpec.ShipperType)
						assert.Equal(t, expected.ShipperSpec.BinaryName, actual.ShipperSpec.BinaryName)
						assert.Equal(t, expected.ShipperSpec.BinaryPath, actual.ShipperSpec.BinaryPath)

						assert.Nil(t, actual.Shipper)
						assert.Len(t, actual.Units, len(expected.Units))
						for i := range expected.Units {
							assertEqualUnitExpectedConfigs(t, &expected.Units[i], &actual.Units[i])
						}
					}
				}
			}
		})
	}
}

func TestInjectingInputPolicyID(t *testing.T) {
	const testRevision = 10
	fleetPolicy := map[string]interface{}{
		"revision": testRevision,
	}

	tests := []struct {
		name   string
		policy map[string]interface{}
		in     map[string]interface{}
		out    map[string]interface{}
	}{
		{"NilEverything", nil, nil, nil},
		{"NilInput", fleetPolicy, nil, nil},
		{"NilPolicy", nil,
			map[string]interface{}{},
			map[string]interface{}{},
		},
		{"EmptyPolicy", map[string]interface{}{},
			map[string]interface{}{},
			map[string]interface{}{},
		},
		{"CreatePolicyRevision", fleetPolicy,
			map[string]interface{}{},
			map[string]interface{}{
				"policy": map[string]interface{}{"revision": testRevision},
			},
		},
		{"NilPolicyObjectType", fleetPolicy,
			map[string]interface{}{
				"policy": nil,
			},
			map[string]interface{}{
				"policy": map[string]interface{}{"revision": testRevision},
			},
		},
		{"InjectPolicyRevision", fleetPolicy,
			map[string]interface{}{
				"policy": map[string]interface{}{"key": "value"},
			},
			map[string]interface{}{
				"policy": map[string]interface{}{"key": "value", "revision": testRevision},
			},
		},
		{"UnknownPolicyObjectType", fleetPolicy,
			map[string]interface{}{
				"policy": map[string]int{"key": 10},
			},
			map[string]interface{}{
				"policy": map[string]int{"key": 10},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			injectInputPolicyID(tc.policy, tc.in)
			assert.Equal(t, tc.out, tc.in)
		})
	}
}

func assertEqualUnitExpectedConfigs(t *testing.T, expected *Unit, actual *Unit) {
	t.Helper()
	assert.Equal(t, expected.ID, actual.ID)
	assert.Equal(t, expected.Type, actual.Type)
	assert.Equal(t, expected.LogLevel, actual.LogLevel)
	assert.Equal(t, expected.Err, actual.Err)
	diff := cmp.Diff(expected.Config, actual.Config, protocmp.Transform())
	assert.Empty(t, diff)
}

func sortComponents(components []Component) {
	for _, comp := range components {
		sort.Slice(comp.Units, func(i, j int) bool {
			return comp.Units[i].ID < comp.Units[j].ID
		})

		// need to sort config.source as well
		for _, unit := range comp.Units {
			if unit.Config == nil || unit.Config.Source == nil {
				continue
			}
			source := unit.Config.Source.AsMap()
			units, found := source["units"]
			if !found {
				continue
			}
			unitsSliceRaw, ok := units.([]interface{})
			if !ok {
				continue
			}

			sort.Slice(unitsSliceRaw, func(i, j int) bool {
				unitsSliceI := unitsSliceRaw[i].(map[string]interface{})
				unitsSliceJ := unitsSliceRaw[j].(map[string]interface{})
				return fmt.Sprint(unitsSliceI["id"]) < fmt.Sprint(unitsSliceJ["id"])
			})
			newSource, err := structpb.NewStruct(source)
			if err != nil {
				panic(fmt.Errorf("failed to create new struct from map: %w", err))
			}
			unit.Config.Source = newSource
		}
	}
	sort.Slice(components[:], func(i, j int) bool {
		return components[i].Units[0].ID < components[j].Units[0].ID
	})
}

func mustExpectedConfigForceType(cfg map[string]interface{}, forceType string) *proto.UnitExpectedConfig {
	res := MustExpectedConfig(cfg)
	res.Type = forceType
	return res
}

type testHeadersProvider struct {
	headers map[string]string
}

func (h *testHeadersProvider) Headers() map[string]string {
	return h.headers
}

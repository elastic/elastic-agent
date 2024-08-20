// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package component

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-ucfg"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/eql"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fake error type used for the test below
type testErr struct {
	data string
}

func (t testErr) Error() string {
	return t.data
}

func TestComponentMarshalError(t *testing.T) {
	testComponent := Component{
		ID:  "test-device",
		Err: testErr{data: "test error value"},
	}
	componentConfigs := []Component{testComponent}

	outData, err := yaml.Marshal(struct {
		Components []Component `yaml:"components"`
	}{
		Components: componentConfigs,
	})
	require.NoError(t, err)
	require.Contains(t, string(outData), "test error value")
}

func TestToComponents(t *testing.T) {
	linuxAMD64Platform := PlatformDetail{
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
			Name:     "Invalid: inputs entry duplicate because of missing id (isolated units)",
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
						"type": "cloudbeat",
					},
					map[string]interface{}{
						"type": "cloudbeat",
					},
				},
			},
			Err: `invalid 'inputs.1.id', has a duplicate id "cloudbeat". Please add a unique value for the 'id' key to each input in the agent policy`,
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
			Name:     "Invalid: inputs entry id not a string (isolated units)",
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
						"type": "cloudbeat",
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
			Name:     "Invalid: inputs entry use_output not a string (isolated units)",
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
						"type":       "cloudbeat",
						"id":         "cloudbeat-0",
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
			Name:     "Invalid: inputs entry use_output references unknown output (isolated units)",
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
						"type":       "cloudbeat",
						"id":         "cloudbeat-0",
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
			Name:     "Invalid: inputs entry enabled not a bool (isolated units)",
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
						"type":       "cloudbeat",
						"id":         "cloudbeat-0",
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
					InputType:  "unknown",
					OutputType: "elasticsearch",
					ID:         "unknown-default",
					InputSpec:  &InputRuntimeSpec{},
					Err:        ErrInputNotSupported,
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
			Name:     "Invalid: inputs fleet-server doesn't support logstash",
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
					InputType:  "fleet-server",
					OutputType: "logstash",
					ID:         "fleet-server-default",
					Err:        ErrOutputNotSupported,
					InputSpec: &InputRuntimeSpec{
						InputType:  "fleet-server",
						BinaryName: "fleet-server",
						BinaryPath: filepath.Join("..", "..", "specs", "fleet-server"),
					},
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
				Major:  7,
				Minor:  2,
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
					InputType:  "endpoint",
					OutputType: "elasticsearch",
					ID:         "endpoint-default",
					InputSpec: &InputRuntimeSpec{
						InputType:  "endpoint",
						BinaryName: "endpoint-security",
						BinaryPath: filepath.Join("..", "..", "specs", "endpoint-security"),
					},
					Err: NewErrInputRuntimeCheckFail("Elastic Defend doesn't support RHEL7 on arm64"),
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					ID:         "filestream-default",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
			Name:     "Invalid: single input failed to decode into config (isolated units)",
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
						"type":       "cloudbeat",
						"id":         "cloudbeat-0",
						"use_output": "default",
						"enabled":    true,
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-1",
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
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					ID:         "cloudbeat-default-cloudbeat-0",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
							}),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					ID:         "cloudbeat-default-cloudbeat-1",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-1",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-1-unit",
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
			Name:     "Output disabled (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
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
			Name:     "Input disabled (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-1",
						"enabled": false,
					},
					map[string]interface{}{
						"type":    "cloudbeat",
						"id":      "cloudbeat-2",
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
			Name:     "Simple representation (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
						"enabled": true,
					},
					map[string]interface{}{
						"type":    "cloudbeat",
						"id":      "cloudbeat-1",
						"enabled": false,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
			Name:     "Debug log level (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
						"enabled": true,
					},
					map[string]interface{}{
						"type":    "cloudbeat",
						"id":      "cloudbeat-1",
						"enabled": false,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: client.UnitLogLevelDebug,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: client.UnitLogLevelDebug,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
			Name:     "Unique log level (isolated units)",
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
						"type":      "cloudbeat",
						"id":        "cloudbeat-0",
						"enabled":   true,
						"log_level": "debug",
					},
					map[string]interface{}{
						"type":    "cloudbeat",
						"id":      "cloudbeat-1",
						"enabled": false,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: client.UnitLogLevelError,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: client.UnitLogLevelDebug,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
					InputType:  "log",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "log",
								"id":   "logfile-1",
							}),
						},
					},
				},
				{
					InputType:  "log",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
					InputType:  "log",
					OutputType: "logstash",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
					InputType:  "log",
					OutputType: "redis",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
					InputType:  "apm",
					OutputType: "elasticsearch",
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
			Name:     "Complex representation (isolated units)",
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
						"type": "cloudbeat",
						"id":   "cloudbeat-0",
					},
					map[string]interface{}{
						"type": "cloudbeat",
						"id":   "cloudbeat-1",
					},
					map[string]interface{}{
						"type":    "cloudbeat",
						"id":      "cloudbeat-2",
						"enabled": false,
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-3",
						"use_output": "other",
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-4",
						"use_output": "other",
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-5",
						"use_output": "default",
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-6",
						"use_output": "default",
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-7",
						"use_output": "other",
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-8",
						"use_output": "stashit",
					},
					map[string]interface{}{
						"type":       "cloudbeat",
						"id":         "cloudbeat-9",
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
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
							}),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-1",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-1-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-1",
							}),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-other-cloudbeat-3",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-other-cloudbeat-3-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-3",
							}),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-other-cloudbeat-4",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-other-cloudbeat-4-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-4",
							}),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-5",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-5-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-5",
							}, "cloudbeat"),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-6",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-6-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-6",
							}),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-other-cloudbeat-7",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
							}),
						},
						{
							ID:       "cloudbeat-other-cloudbeat-7-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-7",
							}, "cloudbeat"),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "logstash",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-stashit-cloudbeat-8",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:       "cloudbeat-stashit-cloudbeat-8-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-8",
							}, "cloudbeat"),
						},
					},
				},
				{
					InputType:  "cloudbeat",
					OutputType: "redis",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-redis-cloudbeat-9",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "redis",
							}),
						},
						{
							ID:       "cloudbeat-redis-cloudbeat-9-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: mustExpectedConfigForceType(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-9",
							}, "cloudbeat"),
						},
					},
				},
				{
					InputType:  "apm",
					OutputType: "elasticsearch",
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
					InputType:  "log",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "log",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
		},
		{
			Name:     "Headers injection (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
						"enabled": true,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"headers": map[string]interface{}{
									"cloud": "beat",
								},
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"cloud": "beat",
			}},
		},
		{
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
					InputType:  "filestream",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
			Name:     "Headers injection merge (isolated units)",
			Platform: linuxAMD64Platform,
			Policy: map[string]interface{}{
				"outputs": map[string]interface{}{
					"default": map[string]interface{}{
						"type":    "elasticsearch",
						"enabled": true,
						"headers": map[string]interface{}{
							"cloud1": "beat1",
						},
					},
				},
				"inputs": []interface{}{
					map[string]interface{}{
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
						"enabled": true,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "elasticsearch",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "elasticsearch",
								"headers": map[string]interface{}{
									"cloud1": "beat1",
									"cloud2": "beat2",
								},
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"cloud2": "beat2",
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
					InputType:  "filestream",
					OutputType: "kafka",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
			Name:     "Headers injection not injecting kafka (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
						"enabled": true,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "kafka",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "kafka",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"cloud": "beat",
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
					InputType:  "filestream",
					OutputType: "logstash",
					InputSpec: &InputRuntimeSpec{
						InputType:  "filestream",
						BinaryName: "testbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "testbeat"),
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
		{
			Name:     "Headers injection not injecting logstash (isolated units)",
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
						"type":    "cloudbeat",
						"id":      "cloudbeat-0",
						"enabled": true,
					},
				},
			},
			Result: []Component{
				{
					InputType:  "cloudbeat",
					OutputType: "logstash",
					InputSpec: &InputRuntimeSpec{
						InputType:  "cloudbeat",
						BinaryName: "cloudbeat",
						BinaryPath: filepath.Join("..", "..", "specs", "cloudbeat"),
					},
					Units: []Unit{
						{
							ID:       "cloudbeat-default-cloudbeat-0",
							Type:     client.UnitTypeOutput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "logstash",
							}),
						},
						{
							ID:       "cloudbeat-default-cloudbeat-0-unit",
							Type:     client.UnitTypeInput,
							LogLevel: defaultUnitLogLevel,
							Config: MustExpectedConfig(map[string]interface{}{
								"type": "cloudbeat",
								"id":   "cloudbeat-0",
							}),
						},
					},
				},
			},
			headers: &testHeadersProvider{headers: map[string]string{
				"cloud": "beat",
			}},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			runtime, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), scenario.Platform, SkipBinaryCheck())
			require.NoError(t, err)

			result, err := runtime.ToComponents(scenario.Policy, nil, scenario.LogLevel, scenario.headers, map[string]uint64{})
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
						require.NotNil(t, actual.Err, "should have errored")
						assert.Contains(t, actual.Err.Error(), expected.Err.Error())
						assert.EqualValues(t, expected.Units, actual.Units)
					} else {
						assert.NoError(t, actual.Err, "Expected no error for component "+actual.ID)
					}
					assert.Equal(t, expected.InputType, actual.InputType, "%q: component %q has wrong input type", scenario.Name, actual.ID)
					assert.Equal(t, expected.OutputType, actual.OutputType, "%q: component %q has wrong output type", scenario.Name, actual.ID)
					assert.Equal(t, expected.InputSpec.InputType, actual.InputSpec.InputType)
					assert.Equal(t, expected.InputSpec.BinaryName, actual.InputSpec.BinaryName)
					assert.Equal(t, expected.InputSpec.BinaryPath, actual.InputSpec.BinaryPath)
					for i, eu := range expected.Units {
						assert.EqualValues(t, eu.Config, actual.Units[i].Config)
					}
					assert.EqualValues(t, expected.Units, actual.Units)
				}
			}
		})
	}
}

func TestPreventionsAreValid(t *testing.T) {
	// Test that all spec file preventions use valid syntax and variable names.

	specFiles, err := specFilesForDirectory(filepath.Join("..", "..", "specs"))
	require.NoError(t, err)

	// Create placeholder variables containing all valid variable names
	// for spec file prevention conditions. We don't care what the values
	// are, because we aren't checking the behavior of the preventions for
	// specific platforms, just making sure that they don't reference any
	// invalid variables.
	// This test intentionally uses a fixed variable list instead of
	// calling varsForPlatform(), to make sure anyone who adds support for
	// new variables sees this message:
	// If you find yourself wanting to update this test to add a new
	// value because Agent now supports additional variables, make sure
	// you update `docs/component-specs.md` in the same PR to document
	// the change.
	vars, err := transpiler.NewVars("", map[string]interface{}{
		"install": map[string]interface{}{
			"in_default": true,
		},
		"runtime": map[string]interface{}{
			"platform":    "platform",
			"os":          "os",
			"arch":        "arch",
			"native_arch": "native_arch",
			"family":      "family",
			"major":       1,
			"minor":       2,
		},
		"user": map[string]interface{}{
			"root": false,
		},
	}, nil)
	require.NoError(t, err)

	for path, spec := range specFiles {
		for _, input := range spec.Inputs {
			for _, prevention := range input.Runtime.Preventions {
				_, err := eql.Eval(prevention.Condition, vars, false)
				assert.NoErrorf(t, err, "input '%v' in spec file '%v' has error in prevention [%v]",
					input.Name, path, prevention.Condition)
			}
		}
	}
}

func TestSpecDurationsAreValid(t *testing.T) {
	// Test that durations specified in all spec files explicitly specify valid units.

	specFiles, err := specFilesForDirectory(filepath.Join("..", "..", "specs"))
	require.NoError(t, err)

	// Recursively reflect on component.Spec struct to find time.Duration fields
	// and gather their paths.
	for specFilePath, spec := range specFiles {
		specFilePath, err = filepath.Abs(specFilePath)
		require.NoError(t, err)

		// Gather all duration fields' YAML paths so we an check if the
		// value at each path is valid.
		durationFieldPaths := gatherDurationFieldPaths(spec, "")

		// Parse each spec file's YAML into a ucfg.Config object for
		// easy access to field values via their paths.
		data, err := os.ReadFile(specFilePath)
		require.NoError(t, err)

		var v map[string]interface{}
		err = yaml.Unmarshal(data, &v)
		require.NoError(t, err)

		cfg, err := ucfg.NewFrom(v, ucfg.PathSep("."))
		require.NoError(t, err)

		for _, durationFieldPath := range durationFieldPaths {
			exists, err := cfg.Has(durationFieldPath, -1, ucfg.PathSep("."))
			if !exists {
				continue
			}
			require.NoError(t, err)

			value, err := cfg.String(durationFieldPath, -1, ucfg.PathSep("."))
			require.NoError(t, err)

			// Ensure that value can be parsed as a time.Duration. This parsing will
			// fail if there is no unit suffix explicitly specified.
			_, err = time.ParseDuration(value)
			assert.NoErrorf(t, err, "in spec file [%s], field [%s] has invalid value [%s]: %s", specFilePath, durationFieldPath, value, err)
		}
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
		{
			"NilPolicy", nil,
			map[string]interface{}{},
			map[string]interface{}{},
		},
		{
			"EmptyPolicy",
			map[string]interface{}{},
			map[string]interface{}{},
			map[string]interface{}{},
		},
		{
			"CreatePolicyRevision", fleetPolicy,
			map[string]interface{}{},
			map[string]interface{}{
				"policy": map[string]interface{}{"revision": testRevision},
			},
		},
		{
			"NilPolicyObjectType", fleetPolicy,
			map[string]interface{}{
				"policy": nil,
			},
			map[string]interface{}{
				"policy": map[string]interface{}{"revision": testRevision},
			},
		},
		{
			"InjectPolicyRevision", fleetPolicy,
			map[string]interface{}{
				"policy": map[string]interface{}{"key": "value"},
			},
			map[string]interface{}{
				"policy": map[string]interface{}{"key": "value", "revision": testRevision},
			},
		},
		{
			"UnknownPolicyObjectType", fleetPolicy,
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

// TestSignedMarshalUnmarshal will catch if the yaml library will get updated to v3 for example
func TestSignedMarshalUnmarshal(t *testing.T) {
	const data = "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0="
	const signature = "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM="

	signed := Signed{
		Data:      data,
		Signature: signature,
	}

	b, err := yaml.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	var newSigned Signed
	err = yaml.Unmarshal(b, &newSigned)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(signed, newSigned)
	if diff != "" {
		t.Fatal(diff)
	}

	diff = cmp.Diff(true, signed.IsSigned())
	if diff != "" {
		t.Fatal(diff)
	}

	var nilSigned *Signed
	diff = cmp.Diff(false, nilSigned.IsSigned())
	if diff != "" {
		t.Fatal(diff)
	}

	unsigned := Signed{}
	diff = cmp.Diff(false, unsigned.IsSigned())
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestSignedFromPolicy(t *testing.T) {
	const data = "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0="
	const signature = "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM="

	tests := []struct {
		name       string
		policy     map[string]interface{}
		wantSigned *Signed
		wantErr    error
	}{
		{
			name:    "not signed",
			wantErr: ErrNotFound,
		},
		{
			name: "signed nil",
			policy: map[string]interface{}{
				"signed": nil,
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed not map",
			policy: map[string]interface{}{
				"signed": "",
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed empty",
			policy: map[string]interface{}{
				"signed": map[string]interface{}{},
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed missing signature",
			policy: map[string]interface{}{
				"signed": map[string]interface{}{
					"data": data,
				},
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed missing data",
			policy: map[string]interface{}{
				"signed": map[string]interface{}{
					"signaure": signature,
				},
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed data invalid data type",
			policy: map[string]interface{}{
				"signed": map[string]interface{}{
					"data": 1,
				},
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed signature invalid data type",
			policy: map[string]interface{}{
				"signed": map[string]interface{}{
					"signature": 1,
				},
			},
			wantErr: ErrNotFound,
		},
		{
			name: "signed correct",
			policy: map[string]interface{}{
				"signed": map[string]interface{}{
					"data":      data,
					"signature": signature,
				},
			},
			wantSigned: &Signed{
				Data:      data,
				Signature: signature,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := SignedFromPolicy(tc.policy)
			diff := cmp.Diff(tc.wantSigned, signed)
			if diff != "" {
				t.Fatal(diff)
			}

			diff = cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func gatherDurationFieldPaths(s interface{}, pathSoFar string) []string {
	var gatheredPaths []string

	rt := reflect.TypeOf(s)
	rv := reflect.ValueOf(s)

	switch rt.Kind() {
	case reflect.Int64:
		// If this is a time.Duration value, we gather its path.
		if rv.Type().PkgPath() == "time" && rv.Type().Name() == "Duration" {
			gatheredPaths = append(gatheredPaths, pathSoFar)
			return gatheredPaths
		}

	case reflect.Slice:
		// Recurse on slice elements
		for i := 0; i < rv.Len(); i++ {
			morePaths := gatherDurationFieldPaths(rv.Index(i).Interface(), pathSoFar+"."+strconv.Itoa(i))
			gatheredPaths = append(gatheredPaths, morePaths...)
		}
		return gatheredPaths

	case reflect.Struct:
		// Recurse on the struct's fields
		if pathSoFar != "" {
			pathSoFar += "."
		}
		for i := 0; i < rv.NumField(); i++ {
			tags := rt.Field(i).Tag
			yamlTag := tags.Get("yaml")
			yamlFieldName, _, _ := strings.Cut(yamlTag, ",")
			yamlFieldPath := pathSoFar + yamlFieldName

			morePaths := gatherDurationFieldPaths(rv.Field(i).Interface(), yamlFieldPath)
			gatheredPaths = append(gatheredPaths, morePaths...)
		}
		return gatheredPaths

	case reflect.Ptr:
		if rv.IsNil() {
			// Nil pointer, nothing more to do
			return gatheredPaths
		}

		// Recurse on the dereferenced pointer value.
		morePaths := gatherDurationFieldPaths(rv.Elem().Interface(), pathSoFar)
		gatheredPaths = append(gatheredPaths, morePaths...)
		return gatheredPaths
	}

	return gatheredPaths
}

func TestFlattenedDataStream(t *testing.T) {
	expectedNamespace := "test-namespace"
	expectedType := "test-type"
	expectedDataset := "test-dataset"

	policy := map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{
				"type":    "elasticsearch",
				"enabled": true,
			},
		},
		"inputs": []any{
			map[string]any{
				"type":                "filestream",
				"id":                  "filestream-0",
				"enabled":             true,
				"data_stream.type":    expectedType,
				"data_stream.dataset": expectedDataset,
				"data_stream": map[string]any{
					"namespace": expectedNamespace,
				},
			},
		},
	}
	runtime, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), PlatformDetail{}, SkipBinaryCheck())
	if err != nil {
		t.Fatalf("cannot load runtime specs: %s", err)
	}

	result, err := runtime.ToComponents(policy, nil, logp.DebugLevel, nil, map[string]uint64{})
	if err != nil {
		t.Fatalf("cannot convert policy to component: %s", err)
	}

	if len(result) != 1 {
		t.Fatalf("expecting result to have one element, got %d", len(result))
	}

	if len(result[0].Units) != 2 {
		t.Fatalf("expecting result[0].Units to have two elements, got %d", len(result))
	}

	// We do not make assumptions about ordering.
	// Get the input Unit
	var dataStream *proto.DataStream
	for _, unit := range result[0].Units {
		if unit.Err != nil {
			t.Fatalf("unit.Err: %s", unit.Err)
		}
		if unit.Type == client.UnitTypeInput {
			dataStream = unit.Config.DataStream
			break
		}
	}

	if dataStream == nil {
		t.Fatal("DataStream cannot be nil")
	}

	if dataStream.Dataset != expectedDataset {
		t.Errorf("expecting DataStream.Dataset: %q, got: %q", expectedDataset, dataStream.Dataset)
	}
	if dataStream.Type != expectedType {
		t.Errorf("expecting DataStream.Type: %q, got: %q", expectedType, dataStream.Type)
	}
	if dataStream.Namespace != expectedNamespace {
		t.Errorf("expecting DataStream.Namespace: %q, got: %q", expectedNamespace, dataStream.Namespace)
	}
}

func TestFlattenedDataStreamIsolatedUnits(t *testing.T) {
	id0 := "cloudbeat-0"
	id1 := "cloudbeat-1"
	expectedNamespace := map[string]string{
		id0: "test-namespace-0",
		id1: "test-namespace-1",
	}
	expectedType := map[string]string{
		id0: "test-type-0",
		id1: "test-type-1",
	}
	expectedDataset := map[string]string{
		id0: "test-dataset-0",
		id1: "test-dataset-1",
	}

	policy := map[string]any{
		"outputs": map[string]any{
			"default": map[string]any{
				"type":    "elasticsearch",
				"enabled": true,
			},
		},
		"inputs": []any{
			map[string]any{
				"type":                "cloudbeat",
				"id":                  id0,
				"enabled":             true,
				"data_stream.type":    expectedType[id0],
				"data_stream.dataset": expectedDataset[id0],
				"data_stream": map[string]any{
					"namespace": expectedNamespace[id0],
				},
			},
			map[string]any{
				"type":                "cloudbeat",
				"id":                  id1,
				"enabled":             true,
				"data_stream.type":    expectedType[id1],
				"data_stream.dataset": expectedDataset[id1],
				"data_stream": map[string]any{
					"namespace": expectedNamespace[id1],
				},
			},
		},
	}

	linuxAMD64Platform := PlatformDetail{
		Platform: Platform{
			OS:   Linux,
			Arch: AMD64,
			GOOS: Linux,
		},
	}

	runtime, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), linuxAMD64Platform, SkipBinaryCheck())
	if err != nil {
		t.Fatalf("cannot load runtime specs: %s", err)
	}

	result, err := runtime.ToComponents(policy, nil, logp.DebugLevel, nil, map[string]uint64{})
	if err != nil {
		t.Fatalf("cannot convert policy to component: %s", err)
	}

	if len(result) != 2 {
		t.Fatalf("expecting result to have one element, got %d", len(result))
	}

	for _, component := range result {
		if len(component.Units) != 2 {
			t.Fatalf("expecting component.Units to have two elements, got %d", len(component.Units))
		}

		// We do not make assumptions about ordering.
		// Get the input Unit
		var dataStream *proto.DataStream
		for _, unit := range component.Units {
			if unit.Err != nil {
				t.Fatalf("unit.Err: %s", unit.Err)
			}
			if unit.Type == client.UnitTypeInput {
				dataStream = unit.Config.DataStream
				break
			}
		}

		if dataStream == nil {
			t.Fatal("DataStream cannot be nil")
		}

		currentId := component.ID[len(component.ID)-len(id0):]

		if dataStream.Dataset != expectedDataset[currentId] {
			t.Errorf("expecting DataStream.Dataset: %q, got: %q", expectedDataset[currentId], dataStream.Dataset)
		}
		if dataStream.Type != expectedType[currentId] {
			t.Errorf("expecting DataStream.Type: %q, got: %q", expectedType[currentId], dataStream.Type)
		}
		if dataStream.Namespace != expectedNamespace[currentId] {
			t.Errorf("expecting DataStream.Namespace: %q, got: %q", expectedNamespace[currentId], dataStream.Namespace)
		}
	}
}

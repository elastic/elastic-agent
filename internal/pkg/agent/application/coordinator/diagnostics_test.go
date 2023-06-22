// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestCoordinatorExpectedDiagnosticHooks(t *testing.T) {

	expected := []string{
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
	}

	// The YAML we expect to see from the preceding config
	expectedCfg := `
agent:
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
	assert.YAMLEq(t, expected, string(result), "vars diagnostic returned unexpected value")
}

func TestDiagnosticComponentsExpected(t *testing.T) {
	// Create a Coordinator with a test component model and make sure it's
	// reported by the components-expected diagnostic

}

func TestDiagnosticComponentsActual(t *testing.T) {

}

func TestDiagnosticState(t *testing.T) {

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

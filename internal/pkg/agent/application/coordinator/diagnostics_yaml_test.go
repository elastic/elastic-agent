// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
)

func TestMarshalPolicyYAMLMatchesYAMLMarshal(t *testing.T) {
	longText := strings.Repeat("a long value with spaces that yaml.v2 folds at eighty columns ", 4)
	multiLine := "line one\n\n  indented line after a blank line\nlast line with trailing spaces  \n"

	testCases := map[string]map[string]interface{}{
		"nil policy":   nil,
		"empty policy": {},
		"no inputs": {
			"outputs": map[string]interface{}{"default": map[string]interface{}{"type": "elasticsearch"}},
		},
		"null inputs":  {"inputs": nil, "outputs": "x"},
		"empty inputs": {"inputs": []interface{}{}, "outputs": "x"},
		"typed inputs slice": {
			"inputs": []map[string]interface{}{{"id": "a"}, {"id": "b"}},
		},
		"inputs is a map": {
			"inputs": map[string]interface{}{"id": "a"},
		},
		"only inputs": {
			"inputs": []interface{}{map[string]interface{}{"id": "a", "type": "filestream"}},
		},
		"inputs of every shape": {
			"inputs": []interface{}{
				map[string]interface{}{},
				nil,
				"scalar",
				42,
				multiLine,
				longText,
				[]interface{}{"nested", []interface{}{"deeper"}, map[string]interface{}{"k": "v"}},
				[]interface{}{},
				map[interface{}]interface{}{"interface": "keys", 1: "int key"},
				map[string]interface{}{
					"id":      "multi-line",
					"script":  multiLine,
					"leading": "  starts with spaces\nand has two lines",
					"long":    longText,
					"quoted":  "on",
					"empty":   "",
					"streams": []interface{}{
						map[string]interface{}{"long": longText, "script": multiLine},
						map[string]interface{}{"list": []interface{}{longText, multiLine}},
					},
				},
			},
		},
		"key ordering and quoting": {
			"inputs":                     []interface{}{map[string]interface{}{"id": "a"}},
			"a10":                        1,
			"a2":                         2,
			"A":                          3,
			"_x":                         4,
			"inputs2":                    5,
			"input":                      6,
			"on":                         7,
			"123":                        8,
			"key: with colon":            9,
			"":                           10,
			"ünïcödé":                    11,
			strings.Repeat("k", 200):     12,
			"multi\nline key":            13,
			"z" + strings.Repeat(" ", 3): longText,
		},
		"synthetics-like": syntheticsLikePolicy(50),
	}

	for name, policy := range testCases {
		t.Run(name, func(t *testing.T) {
			assertMarshalPolicyYAMLMatches(t, policy)
		})
	}
}

func TestMarshalPolicyYAMLMatchesYAMLMarshalForTestdata(t *testing.T) {
	for _, file := range []string{"testdata/config.yaml", "testdata/config_fleet.yaml"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			require.NoError(t, err)

			// Raw YAML decoding nests map[interface{}]interface{} values.
			policy := mapFromRawYAML(t, string(raw))
			assertMarshalPolicyYAMLMatches(t, policy)

			// The coordinator renders policies through the AST, which nests
			// map[string]interface{} values.
			ast, err := transpiler.NewAST(policy)
			require.NoError(t, err)
			rendered, err := ast.Map()
			require.NoError(t, err)
			assertMarshalPolicyYAMLMatches(t, rendered)
		})
	}
}

func TestDiagnosticComputedConfigMatchesYAMLMarshal(t *testing.T) {
	policy := syntheticsLikePolicy(20)
	coord := &Coordinator{derivedConfig: policy}

	hook, ok := diagnosticHooksMap(coord)["computed-config"]
	require.True(t, ok, "diagnostic hooks should have an entry for computed-config")

	want, err := yaml.Marshal(policy)
	require.NoError(t, err)
	require.Equal(t, string(want), string(hook.Hook(context.Background())))
}

func assertMarshalPolicyYAMLMatches(t *testing.T, policy map[string]interface{}) {
	t.Helper()
	want, err := yaml.Marshal(policy)
	require.NoError(t, err)
	got, err := marshalPolicyYAML(policy)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
}

// BenchmarkMarshalPolicyYAML compares encoding a large Synthetics-like policy
// in one yaml.Marshal call with encoding it one input at a time.
func BenchmarkMarshalPolicyYAML(b *testing.B) {
	for _, inputs := range []int{3_000, 20_000} {
		policy := syntheticsLikePolicy(inputs)
		for _, impl := range []struct {
			name    string
			marshal func(map[string]interface{}) ([]byte, error)
		}{
			{"yaml.Marshal", func(p map[string]interface{}) ([]byte, error) { return yaml.Marshal(p) }},
			{"marshalPolicyYAML", marshalPolicyYAML},
		} {
			b.Run(fmt.Sprintf("inputs=%d/%s", inputs, impl.name), func(b *testing.B) {
				b.ReportAllocs()
				var size int
				for b.Loop() {
					out, err := impl.marshal(policy)
					if err != nil {
						b.Fatal(err)
					}
					size = len(out)
				}
				b.ReportMetric(float64(size)/(1<<20), "output-MiB")
			})
		}
	}
}

// syntheticsLikePolicy returns a rendered policy shaped like a Synthetics
// private location policy with n monitors, every fifth one a browser monitor
// with a multi-line inline script.
func syntheticsLikePolicy(n int) map[string]interface{} {
	inputs := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		monitorType, source := "http", "urls"
		value := fmt.Sprintf("https://checkout.example.com/api/v1/health/%d", i)
		if i%5 == 0 {
			monitorType, source = "browser", "source.inline.script"
			value = fmt.Sprintf("step('Go to cart %d', async () => {\n  await page.goto('https://checkout.example.com/cart/%d');\n});\n", i, i)
		}
		id := fmt.Sprintf("synthetics/%s-%08x-6f1c-4b3a-9c2e-%012x-default", monitorType, i, i*7919)
		inputs = append(inputs, map[string]interface{}{
			"id":          id,
			"name":        fmt.Sprintf("Monitor %d-Private location 1-default", i),
			"type":        "synthetics/" + monitorType,
			"use_output":  "default",
			"data_stream": map[string]interface{}{"namespace": "default"},
			"meta":        map[string]interface{}{"package": map[string]interface{}{"name": "synthetics", "version": "1.4.2"}},
			"streams": []interface{}{map[string]interface{}{
				"id":          id,
				"data_stream": map[string]interface{}{"dataset": monitorType, "type": "synthetics"},
				"type":        monitorType,
				"enabled":     true,
				"schedule":    "@every 3m",
				"timeout":     "16s",
				"tags":        []interface{}{"team-checkout", "env:production"},
				source:        value,
				"processors": []interface{}{map[string]interface{}{"add_fields": map[string]interface{}{
					"target": "",
					"fields": map[string]interface{}{"monitor.fleet_managed": true, "config_id": id},
				}}},
			}},
		})
	}
	return map[string]interface{}{
		"id":      "c3a6e6a0-4c1d-11ee-8b6e-6b0f1d2a3c4d",
		"agent":   map[string]interface{}{"monitoring": map[string]interface{}{"enabled": true, "use_output": "default"}},
		"outputs": map[string]interface{}{"default": map[string]interface{}{"type": "elasticsearch", "hosts": []interface{}{"https://es.example.com:443"}}},
		"inputs":  inputs,
	}
}

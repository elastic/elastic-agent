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
// private location policy with n monitors: mostly HTTP monitors, and every
// fifth one a browser monitor with an inline multi-line script and its extra
// network and screenshot streams.
func syntheticsLikePolicy(n int) map[string]interface{} {
	inputs := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		inputs = append(inputs, syntheticsLikeInput(i))
	}
	return map[string]interface{}{
		"id":       "c3a6e6a0-4c1d-11ee-8b6e-6b0f1d2a3c4d",
		"revision": 42,
		"agent": map[string]interface{}{
			"download": map[string]interface{}{"sourceURI": "https://artifacts.elastic.co/downloads/"},
			"monitoring": map[string]interface{}{
				"enabled":    true,
				"use_output": "default",
				"namespace":  "default",
				"logs":       true,
				"metrics":    true,
			},
			"features":   map[string]interface{}{},
			"protection": map[string]interface{}{"enabled": false, "uninstall_token_hash": "", "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"},
		},
		"fleet": map[string]interface{}{"hosts": []interface{}{"https://fleet.example.com:443"}},
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type":    "elasticsearch",
				"hosts":   []interface{}{"https://es.example.com:443"},
				"api_key": "redacted",
				"preset":  "balanced",
			},
		},
		"output_permissions": map[string]interface{}{
			"default": map[string]interface{}{
				"_elastic_agent_checks": map[string]interface{}{"cluster": []interface{}{"monitor"}},
			},
		},
		"signed": map[string]interface{}{
			"data":      strings.Repeat("eyJpZCI6ImMzYTZlNmEwIn0", 8),
			"signature": "MEUCIQDf7m3Kq9a1rD0Kc8w8m0a6sQ9w0l0v1wHqgk7v6P2yNQIgYb0tY0b8u5x0lFJxkX4Qz6Hk5y5v0Hj2T1o2w9kq8cU=",
		},
		"inputs": inputs,
	}
}

func syntheticsLikeInput(i int) map[string]interface{} {
	monitorID := fmt.Sprintf("%08x-6f1c-4b3a-9c2e-%012x", i, i*7919)
	policyID := "c3a6e6a0-4c1d-11ee-8b6e-6b0f1d2a3c4d"
	monitorType := "http"
	if i%5 == 0 {
		monitorType = "browser"
	}

	processors := []interface{}{
		map[string]interface{}{
			"add_fields": map[string]interface{}{
				"target": "",
				"fields": map[string]interface{}{
					"monitor.fleet_managed": true,
					"config_id":             monitorID,
					"meta.space_id":         "default",
				},
			},
		},
	}
	stream := map[string]interface{}{
		"id": fmt.Sprintf("synthetics/%s-%s-%s-%s-default", monitorType, monitorType, monitorID, policyID),
		"data_stream": map[string]interface{}{
			"dataset": monitorType,
			"type":    "synthetics",
		},
		"__ui":              map[string]interface{}{"is_tls_enabled": false},
		"type":              monitorType,
		"enabled":           true,
		"name":              fmt.Sprintf("Monitor %d checking the checkout service", i),
		"id.monitor":        monitorID,
		"origin":            "ui",
		"schedule":          "@every 3m",
		"timeout":           "16s",
		"max_attempts":      2,
		"tags":              []interface{}{"team-checkout", "env:production"},
		"run_from.id":       "private-location-1",
		"run_from.geo.name": "Private location 1",
		"processors":        processors,
	}
	streams := []interface{}{stream}

	if monitorType == "http" {
		stream["urls"] = fmt.Sprintf("https://checkout.example.com/api/v1/health/%d", i)
		stream["max_redirects"] = 0
		stream["mode"] = "any"
		stream["ipv4"] = true
		stream["ipv6"] = true
		stream["check.request.method"] = "GET"
		stream["response.include_body"] = "on_error"
		stream["response.include_headers"] = true
		stream["ssl.verification_mode"] = "full"
		stream["ssl.supported_protocols"] = []interface{}{"TLSv1.1", "TLSv1.2", "TLSv1.3"}
	} else {
		stream["source.inline.script"] = fmt.Sprintf(
			"step('Go to checkout page %d', async () => {\n  await page.goto('https://checkout.example.com/cart/%d');\n});\n\nstep('Check the total', async () => {\n  expect(await page.isVisible('text=Total')).toBeTruthy();\n});\n", i, i)
		stream["screenshots"] = "on"
		stream["throttling"] = map[string]interface{}{"download": 5, "upload": 3, "latency": 20}
		for _, dataset := range []string{"browser.network", "browser.screenshot"} {
			streams = append(streams, map[string]interface{}{
				"id": fmt.Sprintf("synthetics/browser-%s-%s-%s-default", dataset, monitorID, policyID),
				"data_stream": map[string]interface{}{
					"dataset": dataset,
					"type":    "synthetics",
				},
				"processors": processors,
			})
		}
	}

	return map[string]interface{}{
		"id":                fmt.Sprintf("synthetics/%s-%s-%s-default", monitorType, monitorID, policyID),
		"name":              fmt.Sprintf("Monitor %d-Private location 1-default", i),
		"revision":          1,
		"type":              "synthetics/" + monitorType,
		"use_output":        "default",
		"package_policy_id": monitorID + "-" + policyID + "-default",
		"data_stream":       map[string]interface{}{"namespace": "default"},
		"meta": map[string]interface{}{
			"package": map[string]interface{}{"name": "synthetics", "version": "1.4.2"},
		},
		"streams": streams,
	}
}

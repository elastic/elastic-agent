// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
)

// benchmarkPolicy builds a policy with n filestream inputs, each with one stream,
// all sending to a single elasticsearch output. It represents a steady-state
// policy where nothing changes between refreshes.
func benchmarkPolicy(n int) map[string]interface{} {
	inputs := make([]interface{}, n)
	for i := range inputs {
		inputs[i] = map[string]interface{}{
			"type":    "filestream",
			"id":      fmt.Sprintf("filestream-%d", i),
			"enabled": true,
			"streams": []interface{}{
				map[string]interface{}{
					"id":    fmt.Sprintf("filestream-%d-stream-0", i),
					"paths": []interface{}{fmt.Sprintf("/var/log/app-%d/*.log", i)},
					"data_stream": map[string]interface{}{
						"dataset":   fmt.Sprintf("app%d.access", i),
						"type":      "logs",
						"namespace": "default",
					},
				},
			},
		}
	}
	return map[string]interface{}{
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type":    "elasticsearch",
				"enabled": true,
			},
		},
		"inputs": inputs,
	}
}

// BenchmarkToComponentsNoCache measures ToComponents with no cache — every call
// rebuilds all proto.UnitExpectedConfig values from scratch.
func BenchmarkToComponentsNoCache(b *testing.B) {
	specs, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), PlatformDetail{}, SkipBinaryCheck())
	if err != nil {
		b.Fatal(err)
	}
	policy := benchmarkPolicy(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := specs.ToComponents(policy, DefaultRuntimeConfig(), nil, nil, logp.InfoLevel, nil, map[string]uint64{}, map[string]bool{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkToComponentsWithCache measures ToComponents with an ExpectedConfigCache
// across iterations. After the first call the cache is fully warm, so subsequent
// calls skip proto marshalling for unchanged unit configs.
func BenchmarkToComponentsWithCache(b *testing.B) {
	specs, err := LoadRuntimeSpecs(filepath.Join("..", "..", "specs"), PlatformDetail{}, SkipBinaryCheck())
	if err != nil {
		b.Fatal(err)
	}
	policy := benchmarkPolicy(20)
	cache := NewExpectedConfigCache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := specs.ToComponents(policy, DefaultRuntimeConfig(), nil, nil, logp.InfoLevel, nil, map[string]uint64{}, map[string]bool{}, WithExpectedConfigCache(cache)); err != nil {
			b.Fatal(err)
		}
	}
}

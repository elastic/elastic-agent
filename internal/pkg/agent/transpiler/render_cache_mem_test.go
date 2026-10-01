// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func newXXHashDigest() *xxhash.Digest { return xxhash.New() }

// heapInUse forces two GC cycles and returns HeapInuse bytes.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// BenchmarkRenderCacheSteadyState measures the steady-state heap held by the render
// cache after populating it with a k8s-like workload (nInputs × nPods entries).
//
// Run with:
//
//	go test ./internal/pkg/agent/transpiler/... -run=^$ -bench=BenchmarkRenderCacheSteadyState -benchmem -count=1 -benchtime=1x
//
// Reports cache-delta-MB (heap added by the cache vs baseline) and bytes-per-entry.
//
// Two sub-benchmarks show the before/after impact of nilling entry.rendered in put():
//   - rendered_nil=true  — current code: rendered *Dict dropped on cache.put()
//   - rendered_nil=false — old behavior: rendered *Dict retained alongside mapped
func BenchmarkRenderCacheSteadyState(b *testing.B) {
	for _, tc := range []struct {
		nInputs      int
		nPods        int
		keepRendered bool
	}{
		{7, 200, false},
		{7, 200, true},
		{7, 1000, false},
		{7, 1000, true},
	} {
		label := fmt.Sprintf("inputs=%d/pods=%d/rendered_nil=%v", tc.nInputs, tc.nPods, !tc.keepRendered)
		b.Run(label, func(b *testing.B) {
			benchmarkRenderCacheSteadyState(b, tc.nInputs, tc.nPods, tc.keepRendered)
		})
	}
}

func benchmarkRenderCacheSteadyState(b *testing.B, nInputs, nPods int, keepRendered bool) {
	b.Helper()

	// Build a realistic k8s log input template with variable references, nested fields,
	// processors, and several streams — similar to a real Elastic Agent k8s policy.
	inputTemplate := func(i int) map[string]interface{} {
		return map[string]interface{}{
			"id":         fmt.Sprintf("input-%d-${kubernetes.pod.uid}", i),
			"type":       "logfile",
			"use_output": "default",
			"data_stream": map[string]interface{}{
				"namespace": "default",
				"dataset":   fmt.Sprintf("kubernetes.container_logs_%d", i),
				"type":      "logs",
			},
			"streams": []interface{}{
				map[string]interface{}{
					"id":          fmt.Sprintf("logfile-kubernetes.container_logs_%d-${kubernetes.pod.uid}", i),
					"paths":       []interface{}{"${kubernetes.pod.log_path}/*.log"},
					"close_inactive": "5m",
					"scan_frequency": "10s",
					"processors": []interface{}{
						map[string]interface{}{
							"add_fields": map[string]interface{}{
								"target": "kubernetes",
								"fields": map[string]interface{}{
									"pod.name":  "${kubernetes.pod.name}",
									"namespace": "${kubernetes.namespace}",
								},
							},
						},
					},
					"tags": []interface{}{"containerlog", "forwarded"},
				},
				map[string]interface{}{
					"id":    fmt.Sprintf("logfile-kubernetes.stdout_%d-${kubernetes.pod.uid}", i),
					"paths": []interface{}{"/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/*/*.log"},
					"close_inactive": "5m",
				},
			},
		}
	}

	// Build the inputs list as an AST node.
	inputNodes := make([]Node, nInputs)
	for i := range inputNodes {
		ast, err := NewAST(inputTemplate(i))
		if err != nil {
			b.Fatal(err)
		}
		inputNodes[i] = ast.root
	}
	inputs := NewKey("inputs", NewList(inputNodes))

	// Context vars (no dynamic provider): environment and agent metadata.
	ctxVars, err := NewVars("", map[string]interface{}{
		"env": map[string]interface{}{
			"HOME": "/root",
			"PATH": "/usr/bin:/bin",
		},
		"agent": map[string]interface{}{
			"id":      "agent-001",
			"version": "9.0.0",
		},
	}, mapstr.M{}, "env")
	if err != nil {
		b.Fatal(err)
	}
	ctxVars.SetCacheKey("ctx")

	// Per-pod vars: each pod gets its own kubernetes namespace with realistic metadata.
	podVars := make([]*Vars, nPods)
	for i := range podVars {
		podName := fmt.Sprintf("pod-%05d", i)
		ns := fmt.Sprintf("namespace-%d", i%10)
		uid := fmt.Sprintf("uid-%05d", i)
		logPath := fmt.Sprintf("/var/log/pods/%s_%s_%s", ns, podName, uid)

		procs := Processors{
			{
				"add_fields": map[string]interface{}{
					"target": "kubernetes",
					"fields": map[string]interface{}{
						"pod.name":   podName,
						"namespace":  ns,
						"node.name":  fmt.Sprintf("node-%d", i%5),
						"labels.app": fmt.Sprintf("app-%d", i%20),
					},
				},
			},
		}

		vars, err := NewVarsWithProcessors(
			fmt.Sprintf("kubernetes-%d", i),
			map[string]interface{}{
				"env": map[string]interface{}{
					"HOME": "/root",
					"PATH": "/usr/bin:/bin",
				},
				"agent": map[string]interface{}{
					"id":      "agent-001",
					"version": "9.0.0",
				},
				"kubernetes": map[string]interface{}{
					"pod": map[string]interface{}{
						"name":     podName,
						"uid":      uid,
						"log_path": logPath,
					},
					"namespace": ns,
					"node": map[string]interface{}{
						"name": fmt.Sprintf("node-%d", i%5),
					},
					"labels": map[string]interface{}{
						"app":     fmt.Sprintf("app-%d", i%20),
						"version": "v1.0",
					},
				},
			},
			"kubernetes",
			procs,
			mapstr.M{},
			"env",
			"kubernetes",
		)
		if err != nil {
			b.Fatal(err)
		}
		vars.SetCacheKey(fmt.Sprintf("ctx;kubernetes-%d", i))
		podVars[i] = vars
	}

	allVars := append([]*Vars{ctxVars}, podVars...)

	// Baseline heap: everything built but cache not yet populated.
	// KeepAlive ensures podVars/ctxVars are live up to this point but not beyond,
	// so only allVars and inputs contribute to the baseline reading.
	runtime.KeepAlive(podVars)
	runtime.KeepAlive(ctxVars)
	heapBaseline := heapInUse()

	cache := NewRenderCache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 {
			cache.Reset()
		}
		_, err := RenderInputsCached(inputs, allVars, cache)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	// keepRendered=true simulates the old behavior (before entry.rendered=nil in put).
	// Re-render every input against every vars set and store the *Dict back on the entry,
	// which is exactly what the cache would have held without the nil'ing change.
	if keepRendered {
		hasher := newXXHashDigest()
		for _, vars := range allVars {
			for i, node := range inputNodes {
				dict, ok := node.(*Dict)
				if !ok {
					continue
				}
				key := renderKey{input: i, varsKey: vars.cacheKey}
				entry := cache.get(key)
				if entry == nil || entry.removed {
					continue
				}
				// Re-render to get the *Dict tree back and store it on the entry.
				fresh, err := renderInput(dict, vars, hasher)
				if err != nil || fresh.removed {
					continue
				}
				entry.rendered = fresh.rendered
			}
		}
	}

	// KeepAlive ensures allVars/inputNodes are live through the keepRendered block above
	// but not beyond, so only the cache contributes to the heap reading below.
	runtime.KeepAlive(allVars)
	runtime.KeepAlive(inputNodes)

	cacheEntries := cache.Len()
	b.ReportMetric(float64(cacheEntries), "cache-entries")

	// Heap after GC with only the cache alive.
	heapWithCache := heapInUse()

	// Delta = steady-state heap added by the cache entries.
	var cacheHeap int64
	if int64(heapWithCache) > int64(heapBaseline) {
		cacheHeap = int64(heapWithCache) - int64(heapBaseline)
	}
	b.ReportMetric(float64(cacheHeap)/(1024*1024), "cache-delta-MB")
	if cacheEntries > 0 {
		b.ReportMetric(float64(cacheHeap)/float64(cacheEntries), "bytes-per-entry")
	}

	// Keep cache alive through the heap measurement.
	runtime.KeepAlive(cache)
}

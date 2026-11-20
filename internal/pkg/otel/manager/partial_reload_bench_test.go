// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"
	"testing"

	"go.opentelemetry.io/collector/featuregate"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/testing/benchmarks"
)

// BenchmarkBuildMergedConfig benchmarks the full buildMergedConfig call for a
// filestream component with 1, 10, 50, and 90 container-log streams.
//
// The coordinator calls buildMergedConfig on every component model update. It
// merges the per-component OTel configs via confmap.Conf.Merge, which deep-copies
// the accumulated map on every call when the confmap.enableMergeAppendOption
// feature gate is enabled (the agent always enables it, see cmd/run.go).
//
// The 90-stream case matches the peak load from the 80-pod k8s benchmark
// (testing/integration/k8s/otel_partial_reload_test.go: 80 base + 5 swing pods,
// one stream per container, plus a few system pods). The CPU profile from that run
// showed buildMergedConfig / translate.GetOtelConfig / mergeWithExtensions /
// copystructure.Copy consuming ~44 % of the agent process across a 30 s window.
//
// Run with a CPU profile:
//
//	go test -run '^$' -bench=BenchmarkBuildMergedConfig -benchmem \
//	    -cpuprofile=cpu.pprof ./internal/pkg/otel/manager/
//	go tool pprof -top -cum cpu.pprof
func BenchmarkBuildMergedConfig(b *testing.B) {
	// Reproduce the production hot path: the agent process always enables this
	// gate, which routes confmap.Conf.Merge through koanf/maps.Copy →
	// copystructure.Copy.
	if err := featuregate.GlobalRegistry().Set("confmap.enableMergeAppendOption", true); err != nil {
		b.Fatalf("failed to enable confmap.enableMergeAppendOption: %v", err)
	}

	orig := paths.Top()
	paths.SetTop(b.TempDir())
	b.Cleanup(func() { paths.SetTop(orig) })

	agentInfo := &info.AgentInfo{}
	mCfg := monitoringCfg.DefaultConfig()

	for _, n := range []int{1, 10, 50, 90} {
		b.Run(fmt.Sprintf("streams=%d", n), func(b *testing.B) {
			l, _ := loggertest.New("bench")
			m := &OTelManager{managerLogger: l}
			update := configUpdate{
				components:    []component.Component{benchmarks.FilestreamComponent(n)},
				monitoringCfg: mCfg,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := m.buildMergedConfig(update, agentInfo, l); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package benchmarks

import (
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent/pkg/component"
)

// BenchmarkExpectedConfig benchmarks the full ExpectedConfig call for a
// filestream input with 1, 10, 50, and 90 container-log streams.
//
// This is the elastic-agent's per-update work on the process-runtime side: the
// coordinator calls ExpectedConfig once per input on every coordinator cycle to
// serialise the input config into a proto.UnitExpectedConfig.  The dominant cost
// is go-ucfg normalisation (deDotDataStream → config.NewConfigFrom → cfg.Unpack).
//
// The OTel-runtime counterpart, which merges per-component OTel configs on every
// update, lives next to the code it measures:
// internal/pkg/otel/manager/partial_reload_bench_test.go.
//
// Run:
//
//	go test -bench=. -benchmem ./testing/benchmarks/
func BenchmarkExpectedConfig(b *testing.B) {
	for _, n := range []int{1, 10, 50, 90} {
		b.Run(fmt.Sprintf("streams=%d", n), func(b *testing.B) {
			inputCfg := FilestreamInputConfig(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := component.ExpectedConfig(inputCfg)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

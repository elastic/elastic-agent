// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type something struct {
	file   *os.File
	writer *bufio.Writer
}

func (s *something) Temporality(kind metric.InstrumentKind) metricdata.Temporality {
	return metric.DefaultTemporalitySelector(kind)
	//return metricdata.DeltaTemporality
}

func (s *something) Aggregation(kind metric.InstrumentKind) metric.Aggregation {
	return metric.DefaultAggregationSelector(kind)
}

func (s *something) Export(ctx context.Context, met *metricdata.ResourceMetrics) error {

	fmt.Printf("hi fae metrics export for resource %v\n", met.Resource.String())
	for _, sm := range met.ScopeMetrics {
		fmt.Printf("hi fae metrics scope %v, %v:\n", sm.Scope.Name, sm.Scope.SchemaURL)
		for _, m := range sm.Metrics {
			fmt.Printf("hi fae metric %v: %v\n", m.Name, m.Data)
		}
	}
	return nil
}
func (s *something) ForceFlush(ctx context.Context) error {
	return nil
}

func (s *something) Shutdown(ctx context.Context) error {
	return nil
}

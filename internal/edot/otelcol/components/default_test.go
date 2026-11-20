// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package components

import "testing"

func TestPrometheusRemoteWriteV1ReceiverIncluded(t *testing.T) {
	factories, err := Default()()
	if err != nil {
		t.Fatalf("build factories: %v", err)
	}

	for _, factory := range factories.Receivers {
		if factory.Type().String() == "prometheusremotewritev1" {
			return
		}
	}
	t.Fatal("prometheusremotewritev1 receiver is not registered")
}

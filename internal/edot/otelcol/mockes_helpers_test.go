// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelcol

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"go.opentelemetry.io/otel/sdk/metric"

	mockes "github.com/elastic/mock-es/pkg/api"
)

// startMockESDeterministic starts a MockES on a random port using
// httptest.NewServer with a deterministic handler. It registers a cleanup
// function to close the server when the test finishes.
//
// This is a local copy of testing/integration.StartMockESDeterministic so
// these tests can run without the integration build tag.
func startMockESDeterministic(t *testing.T, deterministicHandler func(action mockes.Action, event []byte) int) string {
	t.Helper()
	uid := uuid.Must(uuid.NewV4())

	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))

	mux := http.NewServeMux()
	mux.Handle("/", mockes.NewDeterministicAPIHandler(
		uid,
		"",
		provider,
		time.Now().Add(24*time.Hour),
		0,
		0,
		deterministicHandler,
	))

	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)

	return s.URL
}

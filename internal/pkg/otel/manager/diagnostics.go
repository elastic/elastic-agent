// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

func PerformDiagnosticsExt(ctx context.Context, includeCpuProfile bool) (*elasticdiagnostics.Response, error) {
	// PerformDiagnosticsExt connects to the diagnostics extension over a Unix socket,
	// makes an HTTP request to fetch diagnostic info, and returns the parsed response.
	// If includeCpuProfile is true, it also requests CPU profiling data.

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, paths.DiagnosticsExtensionSocket())
		},
	}
	client := &http.Client{Transport: tr}
	url := "http://localhost/diagnostics"
	if includeCpuProfile {
		url = "http://localhost/diagnostics?cpu=true"
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &elasticdiagnostics.Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return &elasticdiagnostics.Response{}, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return &elasticdiagnostics.Response{}, err
	}

	var respSerialized elasticdiagnostics.Response

	if err := json.Unmarshal(respBytes, &respSerialized); err != nil {
		return &elasticdiagnostics.Response{}, err
	}

	return &respSerialized, nil
}

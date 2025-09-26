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

func PerformDiagnosticsExt(ctx context.Context, cpu bool) (*elasticdiagnostics.Response, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, paths.DiagnosticsExtensionSocket())
		},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodGet, "http://localhost/diagnostics", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var respSerialized elasticdiagnostics.Response

	if err := json.Unmarshal(respBytes, &respSerialized); err != nil {
		return nil, err
	}

	return &respSerialized, nil
}

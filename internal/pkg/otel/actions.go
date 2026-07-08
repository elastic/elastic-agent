// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

// PerformActionExt routes a Fleet action to the beat receiver instance running
// inside EDOT whose elastic-agent component ID is componentID. It connects to
// the elasticdiagnostics extension over its Unix socket, the same transport
// used by PerformDiagnosticsExt, and returns the result map produced by the
// receiver's registered action handler.
//
// If no receiver is currently registered for componentID, or the extension is
// unreachable (EDOT not running), a non-nil error is returned.
func PerformActionExt(ctx context.Context, componentID string, name string, params map[string]interface{}) (map[string]interface{}, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, paths.DiagnosticsExtensionSocket())
		},
	}
	httpClient := &http.Client{Transport: tr}

	body, err := json.Marshal(elasticdiagnostics.ActionRequest{
		ComponentID: componentID,
		Name:        name,
		Params:      params,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal action request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/actions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var actionResp elasticdiagnostics.ActionResponse
	if err := json.Unmarshal(respBytes, &actionResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if actionResp.Error != "" {
			return nil, errors.New(actionResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code performing action: %d", resp.StatusCode)
	}

	if actionResp.Error != "" {
		return actionResp.Result, errors.New(actionResp.Error)
	}

	return actionResp.Result, nil
}

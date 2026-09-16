// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import "github.com/elastic/elastic-agent-client/v7/pkg/proto"

type Response struct {
	ComponentDiagnostics []*proto.ActionDiagnosticUnitResult `json:"diagnostics,omitempty"`
	GlobalDiagnostics    []*proto.ActionDiagnosticUnitResult `json:"global_diagnostics,omitempty"`
}

// ActionRequest is the body POSTed to the /actions route to route a Fleet
// action to a specific beat receiver instance running inside the collector.
// ComponentID is elastic-agent's component ID (e.g. "osquery-default"), not
// the OTel receiver name it is embedded in.
type ActionRequest struct {
	ComponentID string         `json:"component_id"`
	Name        string         `json:"name"`
	Params      map[string]any `json:"params"`
}

// ActionResponse is the response returned by the /actions route. Error is set
// when the registered action handler returned an error; the request is still
// considered delivered (HTTP 200) in that case, mirroring how beats normalizes
// action errors into the result before publishing.
type ActionResponse struct {
	Result map[string]any `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import "github.com/elastic/elastic-agent-client/v7/pkg/proto"

type Response struct {
	ComponentDiagnostics []*proto.ActionDiagnosticUnitResult `json:"diagnostics,omitempty"`
	GlobalDiagnostics    []*proto.ActionDiagnosticUnitResult `json:"global_diagnostics,omitempty"`
}

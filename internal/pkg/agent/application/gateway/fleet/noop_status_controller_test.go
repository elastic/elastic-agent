// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"net/http"

	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
)

type noopController struct{}

func (*noopController) SetAgentID(_ string)                             {}
func (*noopController) RegisterComponent(_ string) status.Reporter      { return &noopReporter{} }
func (*noopController) RegisterLocalComponent(_ string) status.Reporter { return &noopReporter{} }
func (*noopController) RegisterComponentWithPersistance(_ string, _ bool) status.Reporter {
	return &noopReporter{}
}
func (*noopController) RegisterApp(_ string, _ string) status.Reporter { return &noopReporter{} }
func (*noopController) Status() status.AgentStatus                     { return status.AgentStatus{Status: status.Healthy} }
func (*noopController) LocalStatus() status.AgentStatus {
	return status.AgentStatus{Status: status.Healthy}
}
func (*noopController) StatusCode() status.AgentStatusCode               { return status.Healthy }
func (*noopController) UpdateStateID(_ string)                           {}
func (*noopController) StatusString() string                             { return "online" }
func (*noopController) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {}

type noopReporter struct{}

func (*noopReporter) Update(_ state.Status, _ string, _ map[string]interface{}) {}
func (*noopReporter) Unregister()                                               {}

package elasticdiagnosticsextension

import "github.com/elastic/elastic-agent-client/v7/pkg/proto"

type Response struct {
	ComponentDiagnostics []*proto.ActionDiagnosticUnitResult `json:"diagnostics,omitempty"`
	GlobalDiagnostics    []*proto.ActionDiagnosticUnitResult `json:"global_diagnostics,omitempty"`
}

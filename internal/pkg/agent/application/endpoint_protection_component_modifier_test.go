// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/pkg/component"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestEndpointProtectionComponentModifier(t *testing.T) {
	compModifier := EndpointProtectionComponentModifier()

	tests := []struct {
		name      string
		comps     []component.Component
		cfg       map[string]interface{}
		wantComps []component.Component
		wantErr   error
	}{
		{
			name: "nil",
		},
		{
			name: "non endpoint",
			comps: []component.Component{
				{
					ID: "asdfasd",
					InputSpec: &component.InputRuntimeSpec{
						InputType: "osquery",
					},
					Units: []component.Unit{
						{
							ID:   "34534",
							Type: client.UnitTypeInput,
						},
					},
				},
			},
			wantComps: []component.Component{
				{
					ID: "asdfasd",
					InputSpec: &component.InputRuntimeSpec{
						InputType: "osquery",
					},
					Units: []component.Unit{
						{
							ID:   "34534",
							Type: client.UnitTypeInput,
						},
					},
				},
			},
		},
		{
			name: "endpoint",
			comps: []component.Component{
				{
					ID: "asdfasd",
					InputSpec: &component.InputRuntimeSpec{
						InputType: "endpoint",
					},
					Units: []component.Unit{
						{
							ID:   "34534",
							Type: client.UnitTypeInput,
							Config: &proto.UnitExpectedConfig{
								Type:   "endpoint",
								Source: &structpb.Struct{},
							},
						},
					},
				},
			},
			cfg: map[string]interface{}{
				"agent": map[string]interface{}{
					"protection": map[string]interface{}{
						"enabled":              true,
						"signing_key":          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A==",
						"uninstall_token_hash": "DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB",
					},
				},
			},
			wantComps: []component.Component{
				{
					ID: "asdfasd",
					InputSpec: &component.InputRuntimeSpec{
						InputType: "endpoint",
					},
					Units: []component.Unit{
						{
							ID:   "34534",
							Type: client.UnitTypeInput,
							Config: &proto.UnitExpectedConfig{
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"protection":{"enabled":true, "signing_key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A==", "uninstall_token_hash":"DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB"}}`))
									if err != nil {
										t.Fatal(err)
									}
									return &source
								}(),
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			comps, err := compModifier(tc.comps, tc.cfg)

			diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}

			// Cumbersome comparison of the source config encoded in protobuf, cmp panics protobufs comparison otherwise
			if len(tc.wantComps) > 0 && len(tc.wantComps[0].Units) > 0 && comps[0].Units[0].Config != nil && comps[0].Units[0].Config.Source != nil {
				m := comps[0].Units[0].Config.Source.AsMap()
				wantM := tc.wantComps[0].Units[0].Config.Source.AsMap()

				diff = cmp.Diff(wantM, m)
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

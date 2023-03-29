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

func TestEndpointSignedComponentModifier(t *testing.T) {
	compModifier := EndpointSignedComponentModifier()

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
				"signed": map[string]interface{}{
					"data":      "eyJpZCI6ImFhZWM4OTYwLWJiYjAtMTFlZC1hYzBkLTVmNjI0YTQxZjM4OCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRW1tckhDSTdtZ2tuZUJlYVJkc2VkQXZBU2l0UHRLbnpPdUlzeHZJRWdGTkFLVlg3MWpRTTVmalo1eUdsSDB0TmJuR2JrU2pVM0VEVUZsOWllQ1J0ME5nPT0ifX19",
					"signature": "MEUCIQCWoScyJW0dejHFxXBTEcSCOZiBHRVMjuJRPwFCwOdA1QIgKrtKUBzkvVeljRtJyMXfD8zIvWjrMzqhSkgjNESPW5E=",
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
									err := source.UnmarshalJSON([]byte(`{"signed":{"data":"eyJpZCI6ImFhZWM4OTYwLWJiYjAtMTFlZC1hYzBkLTVmNjI0YTQxZjM4OCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRW1tckhDSTdtZ2tuZUJlYVJkc2VkQXZBU2l0UHRLbnpPdUlzeHZJRWdGTkFLVlg3MWpRTTVmalo1eUdsSDB0TmJuR2JrU2pVM0VEVUZsOWllQ1J0ME5nPT0ifX19", "signature":"MEUCIQCWoScyJW0dejHFxXBTEcSCOZiBHRVMjuJRPwFCwOdA1QIgKrtKUBzkvVeljRtJyMXfD8zIvWjrMzqhSkgjNESPW5E="}}`))
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

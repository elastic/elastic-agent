// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestInjectProxyEndpointModifier(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://localhost:8080")
	compModifier := InjectProxyEndpointModifier()

	tests := []struct {
		name   string
		comps  []component.Component
		expect []component.Component
	}{
		{
			name: "nil",
		},
		{
			name: "non endpoint",
			comps: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: "osquery",
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"]}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
			expect: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: "osquery",
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"]}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
		},
		{
			name: "proxy set",
			comps: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_url":"https://proxy:8080"}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
			expect: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_url":"https://proxy:8080"}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
		},
		{
			name: "proxy is empty string",
			comps: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_url":""}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
			expect: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_url":""}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
		},
		{
			name: "proxy disable is true",
			comps: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_disable":true}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
			expect: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_disable":true}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
		},
		{
			name: "inject HTTPS_PROXY",
			comps: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"]}`))
									require.NoError(t, err)
									return &source
								}(),
							},
						},
					},
				},
			},
			expect: []component.Component{
				{
					InputSpec: &component.InputRuntimeSpec{
						InputType: endpoint,
					},
					Units: []component.Unit{
						{
							Type: client.UnitTypeOutput,
							Config: &proto.UnitExpectedConfig{
								Type: elasticsearch,
								Source: func() *structpb.Struct {
									var source structpb.Struct
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["https://localhost:9200"],"proxy_url":"https://localhost:8080"}`))
									require.NoError(t, err)
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
			comps, err := compModifier(tc.comps, nil)
			require.NoError(t, err)

			// Cumbersome comparison of the source config encoded in protobuf, cmp panics protobufs comparison otherwise
			if len(tc.expect) > 0 && len(tc.expect[0].Units) > 0 && comps[0].Units[0].Config != nil && comps[0].Units[0].Config.Source != nil {
				got := comps[0].Units[0].Config.Source.AsMap()
				expect := tc.expect[0].Units[0].Config.Source.AsMap()

				diff := cmp.Diff(expect, got)
				require.Empty(t, diff)
			}
		})
	}
}

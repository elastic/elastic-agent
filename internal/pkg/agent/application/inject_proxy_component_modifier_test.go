// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	t.Setenv("HTTP_PROXY", "http://localhost:8081")
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
		{
			name: "hosts present, inject HTTP_PROXY",
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
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["http://localhost:9200"]}`))
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
									err := source.UnmarshalJSON([]byte(`{"type":"elasticsearch","hosts":["http://localhost:9200"],"proxy_url":"http://localhost:8081"}`))
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

func Test_injectProxyURL(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://localhost:8080")
	t.Setenv("HTTP_PROXY", "http://localhost:8081")
	t.Setenv("NO_PROXY", "do.not.inject.proxy.for.me")

	tests := []struct {
		name   string
		m      map[string]interface{}
		hosts  []string
		expect map[string]interface{}
	}{{
		name:  "nil map",
		m:     nil,
		hosts: nil,
	}, {
		name:   "proxy_url defined",
		m:      map[string]interface{}{"key": "value", "proxy_url": "http://proxy:80"},
		hosts:  nil,
		expect: map[string]interface{}{"key": "value", "proxy_url": "http://proxy:80"},
	}, {
		name:   "proxy_disable set",
		m:      map[string]interface{}{"key": "value", "proxy_disable": true},
		hosts:  nil,
		expect: map[string]interface{}{"key": "value", "proxy_disable": true},
	}, {
		name:   "http hosts uses HTTP_PROXY",
		m:      map[string]interface{}{"key": "value"},
		hosts:  []string{"http://example:80"},
		expect: map[string]interface{}{"key": "value", "proxy_url": "http://localhost:8081"},
	}, {
		name:   "https hosts uses HTTPS_PROXY",
		m:      map[string]interface{}{"key": "value"},
		hosts:  []string{"https://example:443"},
		expect: map[string]interface{}{"key": "value", "proxy_url": "https://localhost:8080"},
	},
	{
		name:   "host skipped by NO_PROXY",
		m:      map[string]interface{}{"key": "value"},
		hosts:  []string{"https://do.not.inject.proxy.for.me", "https://do.not.inject.proxy.for.me:8080", "really.do.not.inject.proxy.for.me"},
		expect: map[string]interface{}{"key": "value"},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			injectProxyURL(tc.m, tc.hosts)
			require.Equal(t, tc.expect, tc.m)
		})
	}
}

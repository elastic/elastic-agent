// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gproto "google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type injectedConfigAssertion func(*testing.T, []component.Component)

func allComponentLvlConfigNil(t *testing.T, components []component.Component) {
	for _, comp := range components {
		assert.Nil(t, comp.Component)
	}
}

func apmConfigEqual(apmConfig *proto.APMConfig) injectedConfigAssertion {
	return func(t *testing.T, components []component.Component) {
		for _, comp := range components {
			if !assert.NotNil(t, comp.Component) {
				// component level config is null, move to the next
				continue
			}

			assert.Truef(t, gproto.Equal(comp.Component.ApmConfig, apmConfig), "apmConfig (%v, %v) not equal", comp.Component.ApmConfig, apmConfig)
		}
	}
}

func TestInjectAPMConfig(t *testing.T) {

	apiKey := "apik"
	secret := "🤫"
	type args struct {
		comps []component.Component
		cfg   map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    injectedConfigAssertion
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "No apm or component level config set",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"enabled": true,
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.NoError,
		},
		{
			name: "No apm config but traces enabled - no config is propagated",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"traces": true,
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.NoError,
		},
		{
			name: "Apm config set but traces disabled - no config is propagated",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"traces": false,
							"apm": map[string]any{
								"hosts": []string{
									"https://apmhost1",
									"https://apmhost2",
								},
								"environment":  "apm-unit-tests",
								"api_key":      "apik",
								"secret_token": "🤫",
								"tls": map[string]any{
									"skip_verify": true,
								},
							},
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.NoError,
		},
		{
			name: "Apm config set but no trace flag set - leave components untouched",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"apm": map[string]any{
								"hosts": []string{
									"https://apmhost1",
									"https://apmhost2",
								},
								"environment":  "apm-unit-tests",
								"api_key":      "apik",
								"secret_token": "🤫",
								"tls": map[string]any{
									"skip_verify": true,
								},
							},
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.NoError,
		},
		{
			name: "Apm config set but trace flag set to false - leave components untouched",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"traces": false,
							"apm": map[string]any{
								"hosts": []string{
									"https://apmhost1",
									"https://apmhost2",
								},
								"environment":  "apm-unit-tests",
								"api_key":      "apik",
								"secret_token": "🤫",
								"tls": map[string]any{
									"skip_verify": true,
								},
							},
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.NoError,
		},
		{
			name: "Apm config and trace flag set - fill existing component level config and propagate it to components",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
						Component: &proto.Component{
							Limits: &proto.ComponentLimits{
								GoMaxProcs: 1,
							},
						},
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"traces": true,
							"apm": map[string]any{
								"hosts": []string{
									"https://apmhost1",
									"https://apmhost2",
								},
								"environment":  "apm-unit-tests",
								"api_key":      "apik",
								"secret_token": "🤫",
								"tls": map[string]any{
									"skip_verify": true,
								},
							},
						},
					},
				},
			},
			want: apmConfigEqual(&proto.APMConfig{
				Elastic: &proto.ElasticAPM{
					Environment: "apm-unit-tests",
					APIKey:      &apiKey,
					SecretToken: &secret,
					Hosts: []string{
						"https://apmhost1",
						"https://apmhost2",
					},
					Tls: &proto.ElasticAPMTLS{
						SkipVerify: true,
						ServerCert: "",
						ServerCa:   "",
					},
				},
			}),
			wantErr: assert.NoError,
		},
		{
			name: "Wrong traces flag type (string) - Error",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"enabled": true,
							"traces":  "true",
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.Error,
		},
		{
			name: "Wrong traces flag type (map) - Error",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"enabled": true,
							"traces":  map[string]any{"foo": "bar"},
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.Error,
		},
		{
			name: "Malformed config - Error",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": "some string value",
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.Error,
		},
		{
			name: "Malformed apm config (not a map) - Error",
			args: args{
				comps: []component.Component{
					{
						ID: "some component",
					},
				},
				cfg: map[string]interface{}{
					"agent": map[string]any{
						"monitoring": map[string]any{
							"traces": true,
							"apm":    "some string value",
						},
					},
				},
			},
			want:    allComponentLvlConfigNil,
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InjectAPMConfig(tt.args.comps, tt.args.cfg)
			if !tt.wantErr(t, err, fmt.Sprintf("InjectAPMConfig(%v, %v)", tt.args.comps, tt.args.cfg)) {
				return
			}
			tt.want(t, got)
		})
	}
}

type mockConfigChange struct {
	c *config.Config
}

func (mcc *mockConfigChange) Config() *config.Config {
	return mcc.c
}

func (mcc *mockConfigChange) Ack() error {
	return nil
}

func (mcc *mockConfigChange) Fail(err error) {
	// nothing happens
}
func TestPatchAPMConfig(t *testing.T) {

	type args struct {
		fleetCfg     string
		agentFileCfg string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "No apm config or traces flag",
			args: args{
				fleetCfg: `
                  agent.monitoring:
                    enabled: true
                    logs: true
                    metrics: true
                  `,
				agentFileCfg: `
                  agent.monitoring:
                    enabled: true
                  `,
			},
			want: `
              agent:
                monitoring:
                  enabled: true
                  logs: true
                  metrics: true
              `,
		},
		{
			name: "traces flag set but no APM config",
			args: args{
				fleetCfg: `
                  agent.monitoring:
                    enabled: true
                    logs: true
                    metrics: true
                  `,
				agentFileCfg: `
                  agent.monitoring:
                    enabled: true
                    traces: true
                  `,
			},
			want: `
              agent:
                monitoring:
                  enabled: true
                  logs: true
                  metrics: true
                  traces: true
              `,
		},
		{
			name: "traces flag and APM config set",
			args: args{
				fleetCfg: `
                  agent.monitoring:
                    enabled: true
                    logs: true
                    metrics: true
                  `,
				agentFileCfg: `
                  agent.monitoring:
                    enabled: true
                    traces: true
                    apm:
                      hosts:
                      - https://apmhost1:443
                      environment: test-apm
                      secret_token: secret
                      tls:
                        skip_verify: true
                  `,
			},
			want: `
              agent:
                monitoring:
                  enabled: true
                  logs: true
                  metrics: true
                  traces: true
                  apm:
                    hosts:
                    - https://apmhost1:443
                    environment: test-apm
                    api_key: ""
                    secret_token: secret
                    tls:
                      skip_verify: true
                      server_ca: ""
                      server_certificate: ""
              `,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fleetConf, err := config.NewConfigFrom(tt.args.fleetCfg)
			require.NoError(t, err)
			agtConf, err := config.NewConfigFrom(tt.args.agentFileCfg)
			require.NoError(t, err)
			log, _ := logger.NewTesting(tt.name)
			patcher := PatchAPMConfig(log, agtConf)

			mcc := &mockConfigChange{c: fleetConf}
			patcher(mcc)

			patchedConf, err := mcc.Config().ToMapStr()
			require.NoError(t, err)
			patchedConfBytes, err := yaml.Marshal(patchedConf)
			require.NoError(t, err)

			assert.YAMLEq(t, tt.want, string(patchedConfBytes))
		})
	}
}

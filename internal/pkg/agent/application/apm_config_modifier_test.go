package application

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestInjectAPMConfig(t *testing.T) {
	type args struct {
		comps []component.Component
		cfg   map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []component.Component
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "No apm config set",
			args: args{
				comps: []component.Component{
					{
						ID:  "some component",
						APM: nil,
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
			want: []component.Component{
				{
					ID:  "some component",
					APM: nil,
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.NoError(t, err)
			},
		},
		{
			name: "Apm config set - propagate it to components regardless of traces value",
			args: args{
				comps: []component.Component{
					{
						ID:  "some component",
						APM: nil,
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
			want: []component.Component{
				{
					ID: "some component",
					APM: &component.APMConfig{
						Elastic: &component.ElasticAPM{
							Environment: "apm-unit-tests",
							APIKey:      "apik",
							SecretToken: "🤫",
							Hosts: []string{
								"https://apmhost1",
								"https://apmhost2",
							},
							TLS: config.APMTLS{
								SkipVerify:        true,
								ServerCertificate: "",
								ServerCA:          "",
							},
						},
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InjectAPMConfig(tt.args.comps, tt.args.cfg)
			if !tt.wantErr(t, err, fmt.Sprintf("InjectAPMConfig(%v, %v)", tt.args.comps, tt.args.cfg)) {
				return
			}
			assert.Equalf(t, tt.want, got, "InjectAPMConfig(%v, %v)", tt.args.comps, tt.args.cfg)
		})
	}
}

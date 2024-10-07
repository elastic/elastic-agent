// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

func Test_initTracer(t *testing.T) {
	tenPercentSamplingRate := float32(0.1)

	type args struct {
		agentName string
		version   string
		mcfg      *monitoringCfg.MonitoringConfig
	}
	tests := []struct {
		name    string
		args    args
		want    assert.ValueAssertionFunc // value assertion for *apm.Tracer returned by initTracer
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "monitoring config disabled",
			args: args{
				agentName: "testagent",
				version:   "1.2.3",
				mcfg: &monitoringCfg.MonitoringConfig{
					Enabled: false,
				},
			},
			want:    assert.Nil,
			wantErr: assert.NoError,
		},
		{
			name: "monitoring config enabled but traces disabled",
			args: args{
				agentName: "testagent",
				version:   "1.2.3",
				mcfg: &monitoringCfg.MonitoringConfig{
					Enabled:       true,
					MonitorTraces: false,
				},
			},
			want:    assert.Nil,
			wantErr: assert.NoError,
		},
		{
			name: "traces enabled, no TLS",
			args: args{
				agentName: "testagent",
				version:   "1.2.3",
				mcfg: &monitoringCfg.MonitoringConfig{
					Enabled:       true,
					MonitorTraces: true,
					APM: monitoringCfg.APMConfig{
						Environment: "unit-test",
						APIKey:      "api-key",
						SecretToken: "secret-token",
						Hosts:       []string{"localhost:8888"},
						GlobalLabels: map[string]string{
							"k1": "v1",
							"k2": "v2",
						},
						TLS:          monitoringCfg.APMTLS{},
						SamplingRate: &tenPercentSamplingRate,
					},
				},
			},
			want:    assert.NotNil,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := initTracer(tt.args.agentName, tt.args.version, tt.args.mcfg)
			if got != nil {
				t.Cleanup(func() {
					got.Close()
				})
			}
			if !tt.wantErr(t, err, fmt.Sprintf("initTracer(%v, %v, %v)", tt.args.agentName, tt.args.version, tt.args.mcfg)) {
				return
			}
			tt.want(t, got, "initTracer(%v, %v, %v)", tt.args.agentName, tt.args.version, tt.args.mcfg)
		})
	}
}

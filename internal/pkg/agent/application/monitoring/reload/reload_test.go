// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package reload

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	aConfig "github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestReload(t *testing.T) {
	tcs := []struct {
		name        string
		currEnabled bool
		currMetrics bool
		currRunning bool

		newConfig       string
		expectedRunning bool
		expectedStart   bool
		expectedStop    bool
	}{
		{
			"start with default config",
			false, false, false,
			``,
			true, true, false,
		},
		{
			"start when not running, monitoring enabled",
			false, false, false,
			`
agent.monitoring.enabled: true
`,
			true, true, false,
		},
		{
			"do not start when not running, only metrics enabled",
			false, false, false,
			`
agent.monitoring.enabled: false
agent.monitoring.metrics: true
`,
			false, false, false,
		},

		{
			"stop when running, monitoring disabled",
			true, true, true,
			`
agent.monitoring.enabled: false
`,
			false, false, true,
		},
		{
			"stop stopped server",
			false, false, false,
			`
agent.monitoring.enabled: false
`,
			false, false, false,
		},
		{
			"remain-running-with-blank-config",
			true, true, true,
			``,
			true, true, true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fsc := &fakeServerController{}
			log, _ := loggertest.New(tc.name)
			cfg := &monitoringCfg.MonitoringConfig{
				Enabled:        tc.currEnabled,
				MonitorMetrics: tc.currMetrics,
			}
			r := NewServerReloader(
				func(mcfg *monitoringCfg.MonitoringConfig) (ServerController, error) {
					return fsc, nil
				},
				log,
				cfg,
			)
			r.isServerRunning.Store(tc.currRunning)
			if tc.currRunning {
				r.srvController = fsc
			}

			newCfg := aConfig.MustNewConfigFrom(tc.newConfig)
			require.NoError(t, r.Reload(newCfg))

			require.Equal(t, tc.expectedRunning, r.isServerRunning.Load())
			require.Equal(t, tc.expectedStart, fsc.startTriggered)
			require.Equal(t, tc.expectedStop, fsc.stopTriggered)
		})
	}
}

type fakeServerController struct {
	startTriggered bool
	stopTriggered  bool
}

func (fsc *fakeServerController) Start() { fsc.startTriggered = true }
func (fsc *fakeServerController) Stop() error {
	fsc.stopTriggered = true
	return nil
}
func (fsc *fakeServerController) Reset() {
	fsc.startTriggered = false
	fsc.stopTriggered = false
}

func (fsc *fakeServerController) Addr() net.Addr {
	return nil
}

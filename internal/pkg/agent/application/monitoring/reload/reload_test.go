// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package reload

import (
	"testing"

	"github.com/stretchr/testify/require"

	aConfig "github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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
			"stop when running, monitoring.metrics disabled",
			true, true, true,
			`
agent.monitoring.metrics: false
`,
			false, false, true,
		},
		{
			"stop stopped server",
			false, false, false,
			`
agent.monitoring.metrics: false
`,
			false, false, false,
		},
		{
			"start started server",
			true, true, true,
			`
agent.monitoring.enabled: true
`,
			true, false, false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fsc := &fakeServerController{}
			log, _ := logger.NewTesting(tc.name)
			cfg := &monitoringCfg.MonitoringConfig{
				Enabled:        tc.currEnabled,
				MonitorMetrics: tc.currMetrics,
			}
			r := NewServerReloader(
				func() (ServerController, error) {
					return fsc, nil
				},
				log,
				cfg,
			)
			r.isServerRunning = tc.currRunning
			if tc.currRunning {
				r.s = fsc
			}

			newCfg := aConfig.MustNewConfigFrom(tc.newConfig)
			require.NoError(t, r.Reload(newCfg))

			require.Equal(t, tc.expectedRunning, r.isServerRunning)
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

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/ini.v1"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func TestEnsureSystemdServiceConfigUpToDate(t *testing.T) {
	const unitFileExpectedContents = `
[Unit]
Description=Elastic Agent is a unified agent to observe, monitor and protect your system.
ConditionFileIsExecutable=/usr/bin/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/usr/bin/elastic-agent
WorkingDirectory=/opt/Elastic/Agent
KillMode=process
Restart=always
RestartSec=120
EnvironmentFile=-/etc/sysconfig/elastic-agent

[Install]
WantedBy=multi-user.target
`
	tests := map[string]struct {
		unitFileInitialContents string
		expectedKillMode        string
	}{
		"killmode_process_exists": {
			unitFileInitialContents: unitFileExpectedContents,
			expectedKillMode:        "process",
		},
		"killmode_process_missing": {
			unitFileInitialContents: `
[Unit]
Description=Elastic Agent is a unified agent to observe, monitor and protect your system.
ConditionFileIsExecutable=/usr/bin/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/usr/bin/elastic-agent
WorkingDirectory=/opt/Elastic/Agent
Restart=always
RestartSec=120
EnvironmentFile=-/etc/sysconfig/elastic-agent

[Install]
WantedBy=multi-user.target
`,
			expectedKillMode: "process",
		},
		"killmode_different": {
			unitFileInitialContents: `
[Unit]
Description=Elastic Agent is a unified agent to observe, monitor and protect your system.
ConditionFileIsExecutable=/usr/bin/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/usr/bin/elastic-agent
WorkingDirectory=/opt/Elastic/Agent
Restart=always
RestartSec=120
EnvironmentFile=-/etc/sysconfig/elastic-agent
KillMode=control-group

[Install]
WantedBy=multi-user.target
`,
			expectedKillMode: "control-group",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			unitFilePath := filepath.Join(t.TempDir(), paths.ServiceName+".service")
			err := os.WriteFile(unitFilePath, []byte(test.unitFileInitialContents), 0644)
			require.NoError(t, err)

			err = ensureSystemdServiceConfigUpToDate(unitFilePath)
			require.NoError(t, err)

			cfg, err := ini.Load(unitFilePath)
			require.NoError(t, err)
			require.Equal(t, test.expectedKillMode, cfg.Section("Service").Key("KillMode").Value())
		})
	}
}

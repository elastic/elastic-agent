// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

func TestEscapingSecretsInPolicy(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})
	t.Skip("flaky test: https://github.com/elastic/elastic-agent/issues/6107")
	ctx := context.Background()
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	randId := uuid.Must(uuid.NewV4()).String()
	policyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + randId,
		Namespace:   "default",
		Description: "Test policy " + randId,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policy, err := info.KibanaClient.CreatePolicy(ctx, policyReq)

	pkgPolicyReq := kibana.PackagePolicyRequest{
		Force:     true,
		Name:      fmt.Sprintf("log-%s", randId),
		Namespace: "default",
		PolicyID:  policy.ID,
		Package: kibana.PackagePolicyRequestPackage{
			Name:    "log",
			Version: "2.3.2",
		},
		Vars: map[string]interface{}{}, // Empty as shown in the example
		Inputs: []map[string]interface{}{
			{
				"enabled":         true,
				"policy_template": "logs",
				"type":            "logfile",
				"streams": []map[string]interface{}{
					{
						"data_stream": map[string]interface{}{
							"dataset": "log.logs",
							"type":    "logs",
						},
						"enabled": true,
						"vars": map[string]interface{}{
							"custom": map[string]interface{}{
								"type":  "yaml",
								"value": "testing: $$$$",
							},
							"data_stream.dataset": map[string]interface{}{
								"type":  "text",
								"value": "generic",
							},
							"paths": map[string]interface{}{
								"type":  "text",
								"value": []string{"asdf"},
							},
							"exlude_files": map[string]interface{}{
								"type":  "text",
								"value": []string{},
							},
							"tags": map[string]interface{}{
								"type":  "text",
								"value": []string{},
							},
						},
					},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	_, err = info.KibanaClient.InstallFleetPackage(ctx, pkgPolicyReq)
	require.NoError(t, err)

	err = tools.InstallAgentForPolicy(ctx, t, installOpts, fixture, info.KibanaClient, policy.ID)
	require.NoError(t, err)

	diagZip, err := fixture.ExecDiagnostics(ctx, "diagnostics", "-p")
	require.NoError(t, err)
	extractDir := t.TempDir()
	extractZipArchive(t, diagZip, extractDir)

	preConfPath := filepath.Join(extractDir, "pre-config.yaml")
	preStat, err := os.Stat(preConfPath)
	require.NoErrorf(t, err, "stat file %q failed", preConfPath)
	require.Greaterf(t, preStat.Size(), int64(0), "file %s has incorrect size", preConfPath)
	pref, err := os.Open(preConfPath)
	require.NoErrorf(t, err, "open file %q failed", preConfPath)
	defer pref.Close()

	preConfObj := struct {
		Inputs []map[string]interface{} `yaml:"inputs"`
	}{}
	err = yaml.NewDecoder(pref).Decode(&preConfObj)
	require.NoError(t, err)

	preConfCheck := false

	for _, input := range preConfObj.Inputs {
		if name, ok := input["name"]; ok && name == pkgPolicyReq.Name {
			streamArr, ok := input["streams"].([]interface{})
			require.True(t, ok)

			for _, stream := range streamArr {
				sm, ok := stream.(map[string]interface{})
				require.True(t, ok)
				actual, ok := sm["testing"]
				require.True(t, ok)
				require.Equal(t, "$$$$", actual)
				preConfCheck = true
			}
		}
	}

	require.True(t, preConfCheck)

	rendConfPath := filepath.Join(extractDir, "components", "log-default", "beat-rendered-config.yml")
	rendStat, err := os.Stat(rendConfPath)
	require.NoErrorf(t, err, "stat file %q failed", rendConfPath)
	require.Greaterf(t, rendStat.Size(), int64(0), "file %s has incorrect size", rendConfPath)
	rendf, err := os.Open(rendConfPath)
	require.NoErrorf(t, err, "open file %q failed", rendConfPath)
	defer rendf.Close()

	rendConfObj := struct {
		Inputs []map[string]interface{} `yaml:"inputs"`
	}{}
	err = yaml.NewDecoder(rendf).Decode(&rendConfObj)
	require.NoError(t, err)

	rendConfCheck := false

	for _, input := range rendConfObj.Inputs {
		actual, ok := input["testing"]
		require.True(t, ok)
		require.Equal(t, "$$", actual)
		rendConfCheck = true
	}

	require.True(t, rendConfCheck)
}

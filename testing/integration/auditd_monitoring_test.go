// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

type AuditDRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost string
}

func TestAuditdCorrectBinaries(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	suite.Run(t, &AuditDRunner{info: info})
}

func (runner *AuditDRunner) SetupSuite() {
	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	policyResp, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "auditd_manager", "1.18.3", "auditd_package.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

func (runner *AuditDRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not to get agent status")

	now := time.Now()
	var query map[string]any
	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				// nothing we can do, just log the map
				t.Errorf("executed at %s: %v",
					now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s",
				now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("starting to ES for metrics at %s", now.Format(time.RFC3339Nano))
	require.Eventually(t, func() bool {
		query = genESQuery(agentStatus.Info.ID,
			[][]string{
				{"exists", "field", "auditd.summary.actor.primary"},
			})
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-auditd_manager.auditd*", runner.info.ESClient)
		require.NoError(t, err)
		if res.Hits.Total.Value < 1 {
			return false
		}
		return true
	}, time.Minute*10, time.Second*10, "could not fetch events for auditd_manager")
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrollFIPS enrolls the locally-built FIPS-capable Elastic Agent into a
// FIPS-capable Fleet Server running in ECH, adds an integration
// to this Agent, and checks that data from the integration shows up in Elasticsearch.
// This test proves that it's possible for a local (on-prem) FIPS-capable Elastic Agent
// to enroll into a FIPS-capable Fleet Server (aka Integrations Server) running in ECH,
// while also exercising the connection between Fleet and the Elastic Package Registry (EPR)
// and also ensuring that the data path from Agent to Elasticsearch works as well.
func TestEnrollFIPS(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
		FIPS: true,
	})

	// Select FIPS-capable local Agent artifact
	fixture, err := define.NewFixtureFromLocalFIPSBuild(t, define.Version())
	require.NoError(t, err)

	// Enroll Agent
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

	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, basePolicy)
	require.NoError(t, err)

	// Install system integration
	_, err = tools.InstallPackageFromDefaultFile(ctx, info.KibanaClient, "system", preinstalledPackages["system"], "system_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(t, err)

	// Ensure data from system integration shows up in Elasticsearch
	status, err := fixture.ExecStatus(ctx)
	require.NoError(t, err)

	docs, err := estools.GetResultsForAgentAndDatastream(ctx, info.ESClient, "system.cpu", status.Info.ID)
	assert.NoError(t, err, "error fetching system metrics")
	assert.Greater(t, docs.Hits.Total.Value, 0, "could not find any matching system metrics for agent ID %s", status.Info.ID)
	t.Logf("Generated %d system events", docs.Hits.Total.Value)

}

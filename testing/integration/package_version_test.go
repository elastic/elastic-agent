// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestPackageVersion(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: true,
	})

	f, err := define.NewFixture(t)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = f.Prepare(ctx, fakeComponent, fakeShipper)
	require.NoError(t, err)

	t.Run("check package version without the agent running", testAgentPackageVersion(f, ctx, true))

	// run the agent and check the daemon version as well
	testVersionFunc := func() error {
		// check the version returned by the running agent
		t.Run("check package version while the agent is running", testAgentPackageVersion(f, ctx, false))
		return nil
	}

	err = f.Run(ctx, integrationtest.State{
		AgentState: atesting.NewClientState(client.Healthy),
		// we don't really need a config and a state but the testing fwk wants it anyway
		Configure: simpleConfig2,
		Components: map[string]atesting.ComponentState{
			"fake-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
		},
		After: testVersionFunc,
	})

	require.NoError(t, err)
}

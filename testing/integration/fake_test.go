// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

var simpleConfig1 = `
outputs:
  default:
    type: fake-action-output
    shipper.enabled: true
inputs:
  - id: fake
    type: fake
    state: 1
    message: Configuring
`

var simpleConfig2 = `
outputs:
  default:
    type: fake-action-output
    shipper.enabled: true
inputs:
  - id: fake
    type: fake
    state: 2
    message: Healthy
`

func TestFakeComponent(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: define.Default,
		Local: true,
	})

	f, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = f.Prepare(ctx, fakeComponent, fakeShipper)
	require.NoError(t, err)

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = f.Run(ctx, atesting.State{
		Configure:  simpleConfig1,
		AgentState: atesting.NewClientState(client.Healthy),
		Components: map[string]atesting.ComponentState{
			"fake-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
						State: atesting.NewClientState(client.Configuring),
					},
				},
			},
		},
	}, atesting.State{
		Configure:  simpleConfig2,
		AgentState: atesting.NewClientState(client.Healthy),
		StrictComponents: map[string]atesting.ComponentState{
			"fake-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
			"fake-shipper-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-shipper-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
		},
	})
	require.NoError(t, err)
}

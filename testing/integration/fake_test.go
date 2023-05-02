// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

var fakeComponent = atesting.UsableComponent{
	Name:       "fake",
	BinaryPath: mustAbs(filepath.Join("..", "..", "pkg", "component", "fake", "component", osExt("component"))),
	Spec: &component.Spec{
		Name:    "fake",
		Version: 2,
		Inputs: []component.InputSpec{
			{
				Name:        "fake",
				Description: "A fake input",
				Platforms: []string{
					"container/amd64",
					"container/arm64",
					"darwin/amd64",
					"darwin/arm64",
					"linux/amd64",
					"linux/arm64",
					"windows/amd64",
				},
				Shippers: []string{
					"fake-shipper",
				},
				Command: &component.CommandSpec{},
			},
		},
	},
}

var fakeShipper = atesting.UsableComponent{
	Name:       "fake-shipper",
	BinaryPath: mustAbs(filepath.Join("..", "..", "pkg", "component", "fake", "shipper", osExt("shipper"))),
	Spec: &component.Spec{
		Name:    "fake-shipper",
		Version: 2,
		Shippers: []component.ShipperSpec{
			{
				Name:        "fake-shipper",
				Description: "A fake shipper",
				Platforms: []string{
					"container/amd64",
					"container/arm64",
					"darwin/amd64",
					"darwin/arm64",
					"linux/amd64",
					"linux/arm64",
					"windows/amd64",
				},
				Outputs: []string{
					"fake-action-output",
				},
				Command: &component.CommandSpec{},
			},
		},
	},
}

var simpleConfig1 = `
outputs:
  default:
    type: fake-action-output
    fake-shipper: {}
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
    fake-shipper: {}
inputs:
  - id: fake
    type: fake
    state: 2
    message: Healthy
`

type FakeComponentIntegrationTestSuite struct {
	suite.Suite
	f *atesting.Fixture
}

func (s *FakeComponentIntegrationTestSuite) SetupSuite() {
	f, err := define.Fixture(s.T())
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = f.Prepare(ctx, fakeComponent, fakeShipper)
	s.Require().NoError(err)
	s.f = f
}

func (s *FakeComponentIntegrationTestSuite) TestAllHealthy() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := s.f.Run(ctx, atesting.State{
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
	s.Require().NoError(err)
}

func TestFakeComponentIntegrationTestSuite(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: true,
	})
	suite.Run(t, new(FakeComponentIntegrationTestSuite))
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return abs
}

func osExt(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

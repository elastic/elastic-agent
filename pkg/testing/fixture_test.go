// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

var fakeComponent = UsableComponent{
	Name:       "fake",
	BinaryPath: mustAbs(filepath.Join("..", "component", "fake", "component", osExt("component"))),
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

var fakeShipper = UsableComponent{
	Name:       "fake-shipper",
	BinaryPath: mustAbs(filepath.Join("..", "component", "fake", "shipper", osExt("shipper"))),
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

var simpleConfig = `
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

func TestFixture_Prepare(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	path := fmt.Sprintf("unix://%s.sock", filepath.Join(paths.TempDir(), "elastic-agent-control"))
	_ = path

	l := LocalFetcher("../../build/distributions")
	f, err := NewFixture(t, "8.8.0", WithFetcher(l), WithLogOutput())
	require.NoError(t, err)
	err = f.Prepare(ctx, fakeComponent, fakeShipper)
	require.NoError(t, err)

	err = f.Run(ctx, State{
		Configure:  simpleConfig,
		AgentState: NewClientState(client.Healthy),
		Components: map[string]ComponentState{
			"fake-default": {
				State: NewClientState(client.Healthy),
				Units: map[ComponentUnitKey]ComponentUnitState{
					ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
						State: NewClientState(client.Healthy),
					},
					ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
						State: NewClientState(client.Healthy),
					},
				},
			},
		},
	})
	require.NoError(t, err)
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

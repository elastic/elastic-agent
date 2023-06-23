// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
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

	t.Run("check package version without the agent running", testAgentPackageVersion(ctx, f, true))

	// run the agent and check the daemon version as well
	testVersionFunc := func() error {
		// check the version returned by the running agent
		t.Run("check package version while the agent is running", testAgentPackageVersion(ctx, f, false))

		// change the version in the version file and verify that the agent returns the new value
		t.Run("check package version after updating file", testVersionAfterUpdatingFile(ctx, f))

		// Destructive tests ahead! If you need to do a normal test on a healthy install of agent, put it before the tests below run
		t.Run("remove package versions file and test version again", testAfterRemovingPkgVersionFiles(f))

		return nil
	}

	err = f.Run(ctx, atesting.State{
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

func testVersionAfterUpdatingFile(ctx context.Context, f *atesting.Fixture) func(*testing.T) {

	return func(t *testing.T) {
		pkgVersionFiles := findPkgVersionFiles(t, f.WorkDir())

		testVersion := "1.2.3-test-abcdef"

		for _, pkgVerFile := range pkgVersionFiles {
			err := os.WriteFile(pkgVerFile, []byte(testVersion), 0o644)
			require.NoError(t, err)
		}

		testAgentPackageVersion(ctx, f, false)
	}
}

func testAfterRemovingPkgVersionFiles(f *atesting.Fixture) func(*testing.T) {
	return func(t *testing.T) {
		matches := findPkgVersionFiles(t, f.WorkDir())

		for _, m := range matches {
			t.Logf("removing package version file %q", m)
			err := os.Remove(m)
			require.NoErrorf(t, err, "error removing package version file %q", m)
		}

		// check the version returned by the running agent
		actualVersionBytes := getAgentVersion(t, f, context.Background(), false)

		actualVersion := unmarshalVersionOutput(t, actualVersionBytes, "binary")

		assert.Truef(t, strings.HasSuffix(actualVersion, "unknown_package_version"), actualVersion, "binary version does not match package version")
	}

}

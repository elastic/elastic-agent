// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/version"
)

func TestPackageVersion(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: true,
	})

	f, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = f.Prepare(ctx, fakeComponent, fakeShipper)
	require.NoError(t, err)

	t.Run("check package version without the agent running", testAgentPackageVersion(ctx, f, true))

	// run the agent and check the daemon version as well
	t.Run("check package version while the agent is running", testVersionWithRunningAgent(ctx, f))

	// Destructive/mutating tests ahead! If you need to do a normal test on a healthy install of agent, put it before the tests below

	// change the version in the version file and verify that the agent returns the new value
	t.Run("check package version after updating file", testVersionAfterUpdatingFile(ctx, f))

	// remove the pkg version file and check that we return the default beats version
	t.Run("remove package versions file and test version again", testAfterRemovingPkgVersionFiles(ctx, f))
}

func testVersionWithRunningAgent(ctx context.Context, f *atesting.Fixture) func(*testing.T) {

	return func(t *testing.T) {

		testf := func() error {
			testAgentPackageVersion(ctx, f, false)
			return nil
		}

		runAgentWithAfterTest(ctx, f, t, testf)
	}
}

func testVersionAfterUpdatingFile(ctx context.Context, f *atesting.Fixture) func(*testing.T) {

	return func(t *testing.T) {
		pkgVersionFiles := findPkgVersionFiles(t, f.WorkDir())

		testVersion := "1.2.3-test-abcdef"

		for _, pkgVerFile := range pkgVersionFiles {
			err := os.WriteFile(pkgVerFile, []byte(testVersion), 0o644)
			require.NoError(t, err)
		}

		testf := func() error {
			testAgentPackageVersion(ctx, f, false)
			return nil
		}

		runAgentWithAfterTest(ctx, f, t, testf)
	}
}

func testAfterRemovingPkgVersionFiles(ctx context.Context, f *atesting.Fixture) func(*testing.T) {
	return func(t *testing.T) {
		matches := findPkgVersionFiles(t, f.WorkDir())

		for _, m := range matches {
			t.Logf("removing package version file %q", m)
			err := os.Remove(m)
			require.NoErrorf(t, err, "error removing package version file %q", m)
		}
		testf := func() error {
			// check the version returned by the running agent
			stdout, stderr, processState := getAgentVersionOutput(t, f, context.Background(), false)

			binaryActualVersion := unmarshalVersionOutput(t, stdout, "binary")
			assert.Equal(t, version.GetDefaultVersion(), binaryActualVersion, "binary version does not return default beat version when the package version file is missing")
			daemonActualVersion := unmarshalVersionOutput(t, stdout, "daemon")
			assert.Equal(t, version.GetDefaultVersion(), daemonActualVersion, "daemon version does not return default beat version when the package version file is missing")
			assert.True(t, processState.Success(), "elastic agent version command should be successful even if the pkg version is not found")

			assert.Contains(t, string(stderr), "Error initializing version information")

			return nil
		}

		runAgentWithAfterTest(ctx, f, t, testf)
	}

}

func runAgentWithAfterTest(ctx context.Context, f *atesting.Fixture, t *testing.T, testf func() error) {

	err := f.Run(ctx, atesting.State{
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
		After: testf,
	})

	require.NoError(t, err)

}

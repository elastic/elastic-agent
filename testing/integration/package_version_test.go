// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/version"
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

		// Destructive tests ahead! If you need to do a normal test on a healthy install of agent, put it before the tests below run
		t.Run("remove package versions file and test version again", testAfterRemovingPkgVersionFiles(t, f))

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

func testAfterRemovingPkgVersionFiles(t *testing.T, f *atesting.Fixture) func(*testing.T) {
	return func(t *testing.T) {
		installFS := os.DirFS(f.WorkDir())
		matches := []string{}
		err := fs.WalkDir(installFS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.Name() == version.PackageVersionFileName {
				matches = append(matches, path)
			}
			return nil
		})
		require.NoError(t, err)

		t.Logf("package version files found: %v", matches)

		for _, m := range matches {
			vFile := filepath.Join(f.WorkDir(), m)
			t.Logf("removing package version file %q", vFile)
			err = os.Remove(vFile)
			require.NoErrorf(t, err, "error removing package version file %q", vFile)
		}

		// check the version returned by the running agent
		actualVersionBytes := getAgentVersion(t, f, context.Background(), false)

		actualVersion := unmarshalVersionOutput(t, actualVersionBytes, "binary")

		assert.Truef(t, strings.HasSuffix(actualVersion, "unknown_package_version"), actualVersion, "binary version does not match package version")
	}

}

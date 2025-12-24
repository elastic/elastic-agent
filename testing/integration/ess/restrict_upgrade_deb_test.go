// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestRestrictUpgradeDeb(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Deb,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "ubuntu",
			},
			{
				Type:   define.Linux,
				Distro: "debian",
			},
		},
	})
	t.Run("when agent is deployed via deb, a user should not be able to upgrade the agent using the cli", func(t *testing.T) {
		ctx := context.Background()

		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("deb"))
		require.NoError(t, err)
		installOpts := atesting.InstallOpts{
			NonInteractive: true,
			Privileged:     true,
			Force:          true,
		}

		_, err = fixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoError(t, err)

		assert.Eventuallyf(t, func() bool {
			// Note that this updates err in the parent function
			err = fixture.IsHealthyOrDegradedFromOutput(ctx)

			return err == nil
		}, 5*time.Minute, time.Second, "Elastic-Agent did not report healthy.")
		if err != nil {
			t.Logf("Agent status error: \"%v\"", err)

			status, err := fixture.ExecStatus(ctx)
			require.NoError(t, err, "must get Agent status")

			require.FailNow(t, "Agent status:", status)
		}

		out, err := fixture.Exec(ctx, []string{"upgrade", "1.0.0"})
		require.Error(t, err)
		require.Contains(t, string(out), coordinator.ErrNotUpgradable.Error())

	})
}

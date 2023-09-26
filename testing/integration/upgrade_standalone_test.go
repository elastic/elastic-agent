// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	versionList, err := upgradetest.GetUpgradableVersions(ctx, define.Version())
	require.NoError(t, err)

	for _, startVersion := range versionList {
		t.Run(fmt.Sprintf("Upgrade %s to %s", startVersion, define.Version()), func(t *testing.T) {
			startFixture, err := atesting.NewFixture(
				t,
				startVersion.String(),
				atesting.WithFetcher(atesting.ArtifactFetcher()),
			)
			require.NoError(t, err, "error creating previous agent fixture")

			endFixture, err := define.NewFixture(t, define.Version())
			require.NoError(t, err)

			err = upgradetest.PerformUpgrade(ctx, startFixture, endFixture, t)
			assert.NoError(t, err)
		})
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func TestStandaloneUpgrade(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Upgrade,
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// test 2 current 8.x version and 1 previous 7.x version
	versionList, err := upgradetest.GetUpgradableVersions(ctx, define.Version(), 2, 1)
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

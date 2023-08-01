// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestSimple(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{
				Type: define.Linux,
				Arch: define.AMD64,
			},
		},
	})

	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(context.Background())
	require.NoError(t, err)

	output, err := fixture.Install(context.Background(), &atesting.InstallOpts{Force: true})
	require.NoError(t, err, string(output))

	<-time.After(15 * time.Second)

	// force failure to cause diagnostics
	t.Fatalf("failed on purpose")
}

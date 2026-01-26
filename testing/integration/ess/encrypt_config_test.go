// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestEncryptConfig(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(t.Context(), fakeComponent)
	require.NoError(t, err)

	out, err := fixture.Exec(t.Context(), []string{"encrypt-config"})
	require.NoErrorf(t, err, "Unexpected error running elastic-agent encrypt-config output: %s", string(out))

	_, err = os.Stat(filepath.Join(fixture.WorkDir(), "fleet.enc"))
	require.NoError(t, err)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/installtest"
)

func TestInstallPrivilegedWithoutBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{Force: true, Privileged: true}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Unprivileged: false}))

	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))

	t.Run("check second agent installs with --develop", func(t *testing.T) {
		// Get path to Elastic Agent executable
		devFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		// Prepare the Elastic Agent so the binary is extracted and ready to use.
		err = devFixture.Prepare(ctx)
		require.NoError(t, err)

		devOpts := &atesting.InstallOpts{Force: true, Privileged: true, Develop: true}
		devOut, err := devFixture.Install(ctx, devOpts)
		if err != nil {
			t.Logf("install --develop output: %s", devOut)
			require.NoError(t, err)
		}
		require.NoError(t, installtest.CheckSuccess(ctx, fixture, installtest.DevelopTopPath(), &installtest.CheckOpts{Unprivileged: false, Develop: true}))
	})
}

func TestInstallPrivilegedWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// Set up random temporary directory to serve as base path for Elastic Agent
	// installation.
	tmpDir := t.TempDir()
	randomBasePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{
		BasePath:   randomBasePath,
		Force:      true,
		Privileged: true,
	}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(randomBasePath, "Elastic", "Agent")
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Unprivileged: false}))
	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))

	t.Run("check second agent installs with --develop", func(t *testing.T) {
		// Get path to Elastic Agent executable
		devFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		// Prepare the Elastic Agent so the binary is extracted and ready to use.
		err = devFixture.Prepare(ctx)
		require.NoError(t, err)

		devOpts := &atesting.InstallOpts{BasePath: randomBasePath, Force: true, Privileged: true, Develop: true}
		devOut, err := devFixture.Install(ctx, devOpts)
		if err != nil {
			t.Logf("install --develop output: %s", devOut)
			require.NoError(t, err)
		}

		devTopPath := filepath.Join(randomBasePath, "Elastic", paths.DevelopmentInstallDirName)
		require.NoError(t, installtest.CheckSuccess(ctx, fixture, devTopPath, &installtest.CheckOpts{Unprivileged: false, Develop: true}))
	})
}

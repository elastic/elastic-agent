// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"debug/buildinfo"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// TestVerifyFIPSBinary uses go command line tools to verify that the agent binary has FIPS indicators.
func TestVerifyFIPSBinary(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: FIPS,
		Sudo:  false,
		Local: true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	path := fixture.BinaryPath()
	info, err := buildinfo.ReadFile(path)
	require.NoError(t, err)

	checkLinks := false
	foundTags := false
	foundExperiment := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "-tags":
			foundTags = true
			require.Contains(t, setting.Value, "requirefips")
			continue
		case "GOEXPERIMENT":
			foundExperiment = true
			require.Contains(t, setting.Value, "systemcrypto")
			continue
		case "-ldflags":
			if !strings.Contains(setting.Value, "-s") {
				checkLinks = true
				continue
			}
		}
	}

	require.True(t, foundTags, "Did not find -tags within binary description")
	require.True(t, foundExperiment, "Did not find GOEXPERIMENT within binary description")

	if checkLinks {
		t.Log("checking artifact symbols")
		cmd := exec.CommandContext(ctx, "go", "tool", "nm", path)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		require.Contains(t, string(output), "OpenSSL_version", "Unable to find OpenSSL symbol links within binary")
	}
}

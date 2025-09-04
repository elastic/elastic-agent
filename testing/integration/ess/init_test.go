// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/process"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/installtest"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestInitOrderNotDegraded(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
		OS: []define.OS{
			{
				Type: define.Windows,
			},
		},
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

	// Check that Agent was installed in default base path in unprivileged mode
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Privileged: true}))

	var withEnv process.CmdOption = func(c *exec.Cmd) error {
		c.Env = append(c.Env, `GODEBUG="inittrace=1"`)
		return nil
	}

	// Switch to privileged mode
	out, err = fixture.Exec(ctx, []string{"version"}, withEnv)
	if err != nil {
		t.Logf("version output: %s", out)
		require.NoError(t, err)
	}

	relativeExec, pointInTimeMs := getAgentServiceStats(string(out))
	require.NotEqual(t, relativeExec, 0, "agent service not initialized")
	require.Less(t, pointInTimeMs, 200, "init took more than 200 ms")
	require.Less(t, relativeExec, 70, "init moved past 70%")
}

func getAgentServiceStats(output string) (int, int) {
	var totalLines, agentServiceIdx int
	var pointInTimeMs int

	for line := range strings.Lines(output) {
		if !strings.HasPrefix(line, "init ") {
			// we only count initializations
			continue
		}

		if strings.HasPrefix(line, "init github.com/elastic/elastic-agent/internal/pkg/agent/agentservice") {
			re := regexp.MustCompile(`@(\d+)\s*ms`)
			match := re.FindStringSubmatch(line)
			if len(match) > 1 {
				pointInTimeMs, _ = strconv.Atoi(match[1])
			}
			agentServiceIdx = totalLines
		}
		totalLines++
	}

	relativeExec := (100 * agentServiceIdx) / totalLines
	return relativeExec, pointInTimeMs
}

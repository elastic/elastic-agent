// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/schollz/progressbar/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	v2proto "github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/installtest"
	"github.com/elastic/elastic-agent/testing/integration"
)

var ErrUnprivilegedMismatch = errors.New("unprivileged state mismatch")

type Logger interface {
	Logf(format string, args ...interface{})
}

func TestSwitchUnprivilegedWithoutBasePath(t *testing.T) {

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
				Type: define.Darwin,
			}, {
				Type: define.Linux,
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
	testSwitchUnprivilegedWithoutBasePathCustomUser(ctx, t, fixture, "", "")
}

func TestSwitchUnprivilegedWithoutBasePathCustomUser(t *testing.T) {
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
				Type: define.Darwin,
			}, {
				Type: define.Linux,
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
	testSwitchUnprivilegedWithoutBasePathCustomUser(ctx, t, fixture, "tester", "testing")
}

func testSwitchUnprivilegedWithoutBasePathCustomUser(ctx context.Context, t *testing.T, fixture *atesting.Fixture, customUsername, customGroup string) {
	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{Force: true, Privileged: true}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// setup user
	if customUsername != "" {
		pt := progressbar.NewOptions(-1)
		_, err = install.EnsureUserAndGroup(customUsername, customGroup, pt, true)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path in privileged mode
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Privileged: true}))

	// Switch to unprivileged mode
	args := []string{"unprivileged", "-f"}
	if customUsername != "" {
		args = append(args, "--user", customUsername)
	}

	if customGroup != "" {
		args = append(args, "--group", customGroup)
	}

	out, err = fixture.Exec(ctx, args)
	if err != nil {
		t.Logf("unprivileged output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent is running in default base path in unprivileged mode
	checks := &installtest.CheckOpts{
		Privileged: false,
		Username:   customUsername,
		Group:      customGroup,
	}
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, checks))
}

func TestSwitchUnprivilegedWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
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

	// When running in unprivileged using a base path the
	// base needs to be accessible by the `elastic-agent-user` user that will be
	// executing the process, but is not created yet. Using a base that exists
	// and is known to be accessible by standard users, ensures this tests
	// works correctly and will not hit a permission issue when spawning the
	// elastic-agent service.
	var basePath string
	switch runtime.GOOS {
	case define.Linux:
		basePath = `/usr`
	case define.Windows:
		basePath = `C:\`
	default:
		// Set up random temporary directory to serve as base path for Elastic Agent
		// installation.
		tmpDir := t.TempDir()
		basePath = filepath.Join(tmpDir, strings.ToLower(randStr(8)))
	}

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := &atesting.InstallOpts{
		BasePath:   basePath,
		Force:      true,
		Privileged: true,
	}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path in privileged mode
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: true}))

	// Switch to unprivileged mode
	out, err = fixture.Exec(ctx, []string{"unprivileged", "-f"})
	if err != nil {
		t.Logf("unprivileged output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent is running in the custom base path in unprivileged mode
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: false}))
}

func TestSwitchToUnprivilegedDeduplication(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		OS: []define.OS{
			{
				Type: define.Darwin,
			}, {
				Type: define.Linux,
			},
		},
		Sudo:  true,  // We require sudo for this test to run `elastic-agent install`.
		Local: false, // not safe to run this test locally as it installs Elastic Agent.
	})

	ctx := context.Background()

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "getting path to Elastic Agent executable failed")

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err, "preparing Elastic Agent fixture failed")

	kibClient := stack.KibanaClient

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.Must(uuid.NewV4()).String()
	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true, // start privileged, then switch
	}
	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, kibClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Log("Waiting for Agent to be healthy...")
	err = WaitHealthyAndUnprivileged(ctx, fixture, false, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err, "waiting for agent to become healthy failed")

	agentID, err := fixture.AgentID(ctx)
	require.NoError(t, err, "retrieving agent ID failed")

	t.Logf("Agent ID: %q", agentID)

	t.Log("Waiting for enrolled Agent status to be online...")
	_, err = backoff.Retry(ctx, func() (bool, error) {
		checkSuccessful := check.FleetAgentStatus(
			ctx, t, kibClient, agentID, "online")()
		if !checkSuccessful {
			return checkSuccessful, fmt.Errorf("agent status is not online")
		}
		return checkSuccessful, nil
	}, backoff.WithMaxElapsedTime(2*time.Minute), backoff.WithBackOff(backoff.NewConstantBackOff(10*time.Second)))

	require.NoError(t, err, "waiting for enrolled agent to be online failed")

	t.Logf("Switching agent privilege level...")

	switchErrg := new(errgroup.Group)

	var actionsCount = 5
	errors := make([]string, actionsCount)
	for i := 0; i < actionsCount; i++ {
		switchErrg.Go(func() error {
			err := fleettools.SwitchAgentToUnprivileged(ctx, kibClient, agentID)
			if err != nil {
				errors[i] = err.Error()
			}
			return err
		})
	}

	switchErr := switchErrg.Wait()
	// log all errors
	require.NoErrorf(t, switchErr, "switching agent privilege level failed: %s", strings.Join(errors, "; "))

	t.Log("Waiting for switched Agent status to be online...")
	_, err = backoff.Retry(ctx, func() (any, error) {
		checkSuccessful := check.FleetAgentStatus(ctx, t, kibClient, agentID, "online")()
		if !checkSuccessful {
			return checkSuccessful, fmt.Errorf("agent status is not online")
		}
		return checkSuccessful, nil
	}, backoff.WithMaxElapsedTime(10*time.Minute), backoff.WithBackOff(backoff.NewConstantBackOff(15*time.Second)))

	require.NoError(t, err, "waiting for switched agent to be online failed")

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = WaitHealthyAndUnprivileged(ctx, fixture, true, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err, "waiting for healthy unprivileged agent failed")
}

func checkHealthyAndUnprivileged(ctx context.Context, f *atesting.Fixture, unprivileged bool) error {
	status, err := f.ExecStatus(ctx)
	if err != nil {
		return err
	}

	if status.State != int(v2proto.State_HEALTHY) {
		return fmt.Errorf("agent state is not healthy: got %d",
			status.State)
	}

	if status.Info.Unprivileged != unprivileged {
		return ErrUnprivilegedMismatch
	}

	return nil
}

func WaitHealthyAndUnprivileged(ctx context.Context, f *atesting.Fixture, unprivileged bool, timeout time.Duration, interval time.Duration, logger Logger) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The deadline was set above, we don't need to check for it.
	deadline, _ := ctx.Deadline()

	t := time.NewTicker(interval)
	defer t.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("failed waiting for healthy agent and unprivileged state (%w): %w", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case <-t.C:
			err := checkHealthyAndUnprivileged(ctx, f, unprivileged)
			// If we're in an upgrade process, the versions might not match
			// so we wait to see if we get to a stable version
			if errors.Is(err, ErrUnprivilegedMismatch) {
				logger.Logf("unprivileged mismatch, ignoring, waiting until deadline: %s", time.Until(deadline))
				continue
			}
			if err == nil {
				return nil
			}
			lastErr = err
			logger.Logf("waiting for healthy agent and proper unprivileged state: %s", err)
		}
	}
}

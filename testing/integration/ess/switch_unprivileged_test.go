// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	v2proto "github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/installtest"
	"github.com/elastic/elastic-agent/testing/integration"
)

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

// TestSwitchToUnprivilegedDeduplication verifies that a PRIVILEGE_LEVEL_CHANGE
// action delivered to an agent that is already running at the target privilege
// level is acked via the dedup branch of handlerPrivilegeLevelChange (handler
// returns nil, agent stays HEALTHY) instead of falling through to the
// "can change privilege level only when running as root/Administrator" error.
//
// We also inject a SETTINGS action with log_level=debug on the first checkin
// so the diagnostic Debugf added in handler_action_privilege_level_change.go
// (issue #14079 investigation) is captured in any artifact from this run.
func TestSwitchToUnprivilegedDeduplication(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		OS: []define.OS{
			{Type: define.Darwin},
			{Type: define.Linux},
		},
		Sudo:  true,
		Local: false,
	})

	ctx, cancel := testcontext.WithTimeout(t, t.Context(), 15*time.Minute)
	defer cancel()

	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8221")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()

	handlers := &fleetservertest.Handlers{
		APIKey:          apiKey.Key,
		EnrollmentToken: "enrollmentToken",
		AgentID:         policy.AgentID, // no enroll handler is called when AgentID is preset
		CheckinFn:       fleetservertest.NewHandlerCheckin(checkinWithAcker.ActionsGenerator()),
		EnrollFn:        fleetservertest.NewHandlerEnroll(policy.AgentID, policy.PolicyID, apiKey),
		AckFn:           fleetservertest.NewHandlerAckWithAcker(checkinWithAcker.Acker()),
		StatusFn:        fleetservertest.NewHandlerStatusHealthy(),
	}

	fleetServer := fleetservertest.NewServer(handlers, fleetservertest.WithRequestLog(t.Logf))
	defer fleetServer.Close()

	// Point the policy's fleet.hosts at the running mock fleet. The policy-change
	// handler at handler_action_policy_change.go:249 validates connectivity to
	// every host in the new policy — leaving the placeholder from
	// createBasicFleetPolicyData would fail DNS and push the agent to state=4
	// before we ever get to the privilege change.
	policy.FleetHosts = []string{fleetServer.LocalhostURL}

	// First checkin: initial POLICY_CHANGE so the agent converges, plus a
	// SETTINGS action setting log_level=debug. The latter ensures the
	// diagnostic log added in handlerPrivilegeLevelChange (issue #14079
	// investigation) shows up in agent logs / any diagnostics bundle.
	policyAction, err := fleetservertest.NewActionWithEmptyPolicyChange("policy-change-1", policy)
	require.NoError(t, err, "failed to create initial policy-change action")
	settingsAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: "settings-debug-log",
		Type:     fleetapi.ActionTypeSettings,
		Data:     `{"log_level":"debug"}`,
	})
	require.NoError(t, err, "failed to create settings action")
	checkinWithAcker.AddCheckin("ack-bootstrap", 0, policyAction, settingsAction)

	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		atesting.WithAllowErrors(),
		atesting.WithLogOutput())
	require.NoError(t, err, "NewFixtureFromLocalBuild failed")
	err = fixture.EnsurePrepared(ctx)
	require.NoError(t, err, "fixture.EnsurePrepared failed")

	out, err := fixture.Install(ctx, &atesting.InstallOpts{
		Force:          true,
		NonInteractive: true,
		Insecure:       true, // mock fleet-server uses plain HTTP
		Privileged:     true, // start privileged, then switch
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServer.LocalhostURL,
			EnrollmentToken: "anythingWillDo",
		},
	})
	require.NoErrorf(t, err, "error installing agent, output: %s", out)

	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)
	require.True(t, WaitHealthyAndUnprivileged(t, ctx, fixture, false, 2*time.Minute, 10*time.Second),
		"agent never became healthy in privileged mode")

	// First PRIVILEGE_LEVEL_CHANGE: privileged → unprivileged (real switch +
	// reexec). The handler at handler_action_privilege_level_change.go takes
	// the isRoot==true branch (stopComponents, SwitchServiceUser, ack, ReExec).
	const privActionData = `{"unprivileged":true,"user_info":{"username":"","groupname":"","password":""}}`
	privAction1, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: "priv-change-1",
		Type:     fleetapi.ActionTypePrivilegeLevelChange,
		Data:     privActionData,
	})
	require.NoError(t, err, "failed to create first privilege-level-change action")
	checkinWithAcker.AddCheckin("ack-priv-1", 0, privAction1)

	require.True(t, WaitHealthyAndUnprivileged(t, ctx, fixture, true, 5*time.Minute, 10*time.Second),
		"agent never became healthy unprivileged after first switch")

	// Second PRIVILEGE_LEVEL_CHANGE (duplicate): the agent is already at the
	// target level, so the handler must take the dedup branch at
	// handler_action_privilege_level_change.go:114-121 — log "already running
	// as user X and group Y, no changes required" and ack. If the regression
	// returns it falls through to "can change privilege level only when
	// running as root/Administrator" and the top-level state goes to FAILED.
	privAction2, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: "priv-change-2",
		Type:     fleetapi.ActionTypePrivilegeLevelChange,
		Data:     privActionData,
	})
	require.NoError(t, err, "failed to create duplicate privilege-level-change action")
	checkinWithAcker.AddCheckin("ack-priv-2", 0, privAction2)

	dedupSubstr := fmt.Sprintf("already running as user %s and group %s",
		install.ElasticUsername, install.ElasticGroupName)
	const failureSubstr = "can change privilege level only when running as root/Administrator"

	require.Eventuallyf(t, func() bool {
		if agentLogContains(t, fixture, failureSubstr) {
			t.Fatalf("agent log contains regression marker %q after duplicate privilege-level-change", failureSubstr)
		}
		return checkinWithAcker.Acked("priv-change-2") && agentLogContains(t, fixture, dedupSubstr)
	}, 3*time.Minute, 5*time.Second,
		"duplicate privilege-level-change never acked with dedup marker %q in agent log", dedupSubstr)

	// Final sanity: agent must remain HEALTHY and unprivileged.
	assert.True(t, WaitHealthyAndUnprivileged(t, ctx, fixture, true, 1*time.Minute, 5*time.Second),
		"agent not healthy and unprivileged after duplicate privilege-level-change")
}

// agentLogContains reports whether any of the installed agent's NDJSON log
// files under <workDir>/data/elastic-agent-*/logs/ contain substr. Errors
// reading individual files are logged and skipped so a transient rotation
// doesn't fail the assertion.
func agentLogContains(t *testing.T, f *atesting.Fixture, substr string) bool {
	t.Helper()
	pattern := filepath.Join(f.WorkDir(), "data", "elastic-agent-*", "logs", "elastic-agent-*.ndjson")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Logf("agentLogContains: glob %q error: %v", pattern, err)
		return false
	}
	for _, p := range matches {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Logf("agentLogContains: read %q error: %v", p, err)
			continue
		}
		if strings.Contains(string(data), substr) {
			return true
		}
	}
	return false
}

// WaitHealthyAndUnprivileged polls the agent's status until it reports
// STATE_HEALTHY with Info.Unprivileged matching the requested value, or until
// timeout. Failures are reported through assert.EventuallyWithT, so the parent
// test is marked failed but execution continues; the bool return lets callers
// short-circuit follow-up steps that depend on the agent being healthy.
func WaitHealthyAndUnprivileged(t *testing.T, ctx context.Context, f *atesting.Fixture, unprivileged bool, timeout time.Duration, interval time.Duration) bool {
	t.Helper()
	return assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, err := f.ExecStatus(ctx)
		if !assert.NoError(collect, err, "fetching agent status failed") {
			return
		}
		assert.Equal(collect, int(v2proto.State_HEALTHY), status.State,
			"agent state not HEALTHY (message: %q)", status.Message)
		assert.Equal(collect, unprivileged, status.Info.Unprivileged,
			"agent unprivileged mismatch")
	}, timeout, interval, "agent never reached HEALTHY+unprivileged=%v", unprivileged)
}

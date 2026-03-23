// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent-libs/testing/proxytest"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestCheckinCompress enrolls an agent into a policy with the checkin_compress feature flag enabled.
// The agent will use a proxy when communicating with fleet-server; the proxy verifies that the Content-Encoding: gzip header is set on at least one checkin request
func TestCheckinCompress(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Use a proxy to check that requests have a Content-Encoding: gzip header.
	proxyCAKey, proxyCACert, _, err := certutil.NewRootCA()
	require.NoError(t, err, "failed creating proxy CA")

	var sawGzipCheckin atomic.Bool
	proxy := proxytest.New(
		t,
		proxytest.WithRequestLog("checkin-compress", t.Logf),
		proxytest.WithMITMCA(proxyCAKey, proxyCACert),
		proxytest.WithServerTLSConfig(&tls.Config{}),
		proxytest.WithVerifyRequest(func(r *http.Request) error {
			if !isAgentCheckinRequest(r) {
				return nil
			}
			if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
				sawGzipCheckin.Store(true)
			}
			return nil
		}),
	)
	err = proxy.Start()
	require.NoError(t, err, "failed starting proxy")
	t.Cleanup(proxy.Close)

	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-checkin-compress-%s", uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: "test policy for checkin compression",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Insecure:       true,
		ProxyURL:       proxy.LocalhostURL,
	}

	policy, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, agentFixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy: %s", policy.ID)

	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)
	require.Eventually(
		t,
		sawGzipCheckin.Load,
		5*time.Minute,
		5*time.Second,
		"expected at least one gzip-compressed checkin request",
	)
}

func isAgentCheckinRequest(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		strings.Contains(r.URL.Path, "/api/fleet/agents/") &&
		strings.HasSuffix(r.URL.Path, "/checkin")
}

// TestEnrollPreservesCheckinConfig verifies that a user-supplied
// fleet.checkin.compression: none in elastic-agent.yml is not
// overwritten with the default (gzip) during enrollment.
//
// The agent is installed with a pre-configured elastic-agent.yml that
// disables checkin compression.  A MITM proxy records every checkin request.
// After the agent connects to Fleet, we wait for at least one checkin and
// then assert that none of them carried a Content-Encoding: gzip header,
// confirming that compression: none survived enrollment.
func TestEnrollPreservesCheckinConfig(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Write elastic-agent.yml with compression: none before the agent is
	// installed.  LoadPersistentConfig reads this file during enrollment and
	// the fix under test ensures that the setting is propagated to fleet.enc.
	const agentYML = "fleet:\n  checkin:\n    compression: none\n"
	err = agentFixture.Configure(ctx, []byte(agentYML))
	require.NoError(t, err, "writing pre-enrollment elastic-agent.yml")

	// Set up a MITM proxy to intercept checkin requests and record whether
	// any of them carry a gzip Content-Encoding header.
	proxyCAKey, proxyCACert, _, err := certutil.NewRootCA()
	require.NoError(t, err, "creating proxy CA")

	var totalCheckins, gzipCheckins atomic.Int32
	proxy := proxytest.New(
		t,
		proxytest.WithRequestLog("enroll-checkin-config", t.Logf),
		proxytest.WithMITMCA(proxyCAKey, proxyCACert),
		proxytest.WithServerTLSConfig(&tls.Config{}),
		proxytest.WithVerifyRequest(func(r *http.Request) error {
			if !isAgentCheckinRequest(r) {
				return nil
			}
			totalCheckins.Add(1)
			if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
				gzipCheckins.Add(1)
			}
			return nil
		}),
	)
	err = proxy.Start()
	require.NoError(t, err, "starting proxy")
	t.Cleanup(proxy.Close)

	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-checkin-config-%s", uuid.Must(uuid.NewV4()).String()),
		Namespace:   "default",
		Description: "test policy for enroll checkin config preservation",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Insecure:       true,
		ProxyURL:       proxy.LocalhostURL,
	}

	_, _, err = tools.InstallAgentWithPolicy(ctx, t, installOpts, agentFixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)

	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)

	// check that we've connected through the proxy
	require.Eventually(
		t,
		func() bool { return totalCheckins.Load() >= 1 },
		5*time.Minute,
		5*time.Second,
		"expected at least one checkin request through the proxy",
	)
	require.Equal(t, int32(0), gzipCheckins.Load(),
		"checkin requests should not be gzip-compressed when compression is none")

	checkinCount := totalCheckins.Load()

	// restart the agent so it needs to reload config.
	err = agentFixture.ExecRestart(ctx)
	require.NoError(t, err)
	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)

	// Wait until at least one checkin request has been observed through the
	// proxy, then assert that none of them used gzip encoding.
	require.Eventually(
		t,
		func() bool { return totalCheckins.Load() > checkinCount },
		5*time.Minute,
		5*time.Second,
		"expected at least one checkin request through the proxy after restart",
	)
	require.Equal(t, int32(0), gzipCheckins.Load(),
		"checkin requests should not be gzip-compressed when compression is none")
}

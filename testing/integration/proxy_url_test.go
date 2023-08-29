// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/proxytest"
	"github.com/elastic/elastic-agent/version"
)

type ProxyURL struct {
	fixture *integrationtest.Fixture

	agentVersion string
	fleet        *fleetservertest.Server
	// fleetNeedsProxyHost is the fleetHost to be set on the agent's enroll.
	// It uses an invalid host so the agent won't be able to connect to fleet
	// unless it's using a proxy.
	fleetNeedsProxyHost string
	proxy1              *proxytest.Proxy
	proxy2              *proxytest.Proxy
	checkinWithAcker    *fleetservertest.CheckinActionsWithAcker
	policyData          fleetservertest.TmplPolicy
}

func SetupTest(t *testing.T) *ProxyURL {
	t.Helper()
	p := &ProxyURL{agentVersion: version.Agent + "-SNAPSHOT"}
	fleetHost := "fleet.elastic.co"

	p.fleetNeedsProxyHost = "http://" + fleetHost
	p.setupFleet(t, p.fleetNeedsProxyHost)

	p.proxy1 = proxytest.New(t,
		proxytest.WithRewrite(fleetHost, "localhost:"+p.fleet.Port),
		proxytest.WithRequestLog("proxy-1", t.Logf),
		proxytest.WithVerboseLog())
	p.proxy2 = proxytest.New(t,
		proxytest.WithRewrite(fleetHost, "localhost:"+p.fleet.Port),
		proxytest.WithRequestLog("proxy-2", t.Logf),
		proxytest.WithVerboseLog())

	f, err := define.NewFixture(t,
		p.agentVersion,
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "SetupTest: NewFixture failed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = f.Prepare(ctx)
	require.NoError(t, err, "SetupTest: fixture.Prepare failed")

	p.fixture = f
	return p
}

func TearDownTest(t *testing.T, p *ProxyURL) {
	t.Helper()
	if p.fixture == nil {
		return // nothing to do
	}

	out, err := p.fixture.Uninstall(context.Background(),
		&integrationtest.UninstallOpts{Force: true})
	if err != nil &&
		!errors.Is(err, integrationtest.ErrNotInstalled) &&
		!strings.Contains(err.Error(), "no such file or directory") {
		t.Log(string(out))
		require.NoError(t, err, "TearDownTest: failed to uninstall agent")
	}
}

func TestProxyURL_EnrollProxyAndNoProxyInThePolicy(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/3154")

	p := SetupTest(t)
	t.Cleanup(func() {
		TearDownTest(t, p)
	})

	ackToken := "ackToken-AckTokenTestNoProxyInThePolicy"

	// now that we have fleet and the proxy running, we can add actions which
	// depend on them.
	action, err := fleetservertest.NewActionWithEmptyPolicyChange(
		"actionID-TestNoProxyInThePolicyActionID", p.policyData)
	require.NoError(t, err, "could not generate action with policy")
	p.checkinWithAcker.AddCheckin(
		ackToken,
		0,
		action,
	)

	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxy1.LocalhostURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleetNeedsProxyHost,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	check.ConnectedToFleet(t, p.fixture)
}

func TestProxyURL_EnrollProxyAndEmptyProxyInThePolicy(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/3154")

	p := SetupTest(t)
	t.Cleanup(func() {
		TearDownTest(t, p)
	})

	ackToken := "AckToken-TestEmptyProxyInThePolicy"

	p.policyData.FleetProxyURL = new(string)
	*p.policyData.FleetProxyURL = ""
	// now that we have fleet and the proxy running, we can add actions which
	// depend on them.
	action, err := fleetservertest.NewActionWithEmptyPolicyChange(
		"actionID-TestEmptyProxyInThePolicy", p.policyData)
	require.NoError(t, err, "could not generate action with policy")
	p.checkinWithAcker.AddCheckin(
		ackToken,
		0,
		action,
	)
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxy1.LocalhostURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleetNeedsProxyHost,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	check.ConnectedToFleet(t, p.fixture)
}

func TestProxyURL_ProxyInThePolicyTakesPrecedence(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/3154")

	p := SetupTest(t)
	t.Cleanup(func() {
		TearDownTest(t, p)
	})

	ackToken := "AckToken-TestValidProxyInThePolicy"

	p.policyData.FleetProxyURL = new(string)
	*p.policyData.FleetProxyURL = p.proxy2.LocalhostURL
	// now that we have fleet and the proxy running, we can add actions which
	// depend on them.
	action, err := fleetservertest.NewActionWithEmptyPolicyChange(
		"actionID-TestValidProxyInThePolicy", p.policyData)
	require.NoError(t, err, "could not generate action with policy")
	p.checkinWithAcker.AddCheckin(
		ackToken,
		0,
		action,
	)
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxy1.LocalhostURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleetNeedsProxyHost,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	check.ConnectedToFleet(t, p.fixture)

	// ensure the agent is communicating through the proxy set in the policy
	want := fleetservertest.NewPathCheckin(p.policyData.AgentID)
	assert.Eventually(t, func() bool {
		for _, r := range p.proxy2.ProxiedRequests() {
			if strings.Contains(r, want) {
				return true
			}
		}

		return false
	}, 5*time.Minute, 5*time.Second,
		"did not find requests to the proxy defined in the policy. Want [%s] on %v",
		p.proxy2.LocalhostURL, p.proxy2.ProxiedRequests())
}

func TestProxyURL_NoEnrollProxyAndProxyInThePolicy(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/3154")

	p := SetupTest(t)
	t.Cleanup(func() {
		TearDownTest(t, p)
	})
	ackToken := "AckToken-TestValidProxyInThePolicy"

	p.policyData.FleetHosts = fmt.Sprintf(`"%s"`, p.fleet.LocalhostURL)
	p.policyData.FleetProxyURL = new(string)
	*p.policyData.FleetProxyURL = p.proxy2.LocalhostURL
	// now that we have fleet and the proxy running, we can add actions which
	// depend on them.
	action, err := fleetservertest.NewActionWithEmptyPolicyChange(
		"actionID-TestValidProxyInThePolicy", p.policyData)
	require.NoError(t, err, "could not generate action with policy")
	p.checkinWithAcker.AddCheckin(
		ackToken,
		0,
		action,
	)
	t.Logf("fleet: %s, proxy1: %s, proxy2: %s",
		p.fleet.LocalhostURL,
		p.proxy1.LocalhostURL,
		p.proxy2.LocalhostURL)
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleet.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	check.ConnectedToFleet(t, p.fixture)

	// ensure the agent is communicating through the new proxy
	if !assert.Eventually(t, func() bool {
		for _, r := range p.proxy2.ProxiedRequests() {
			if strings.Contains(
				r,
				fleetservertest.NewPathCheckin(p.policyData.AgentID)) {
				return true
			}
		}

		return false
	}, 5*time.Minute, 5*time.Second) {
		t.Errorf("did not find requests to the proxy defined in the policy")
	}
}

func TestProxyURL_RemoveProxyFromThePolicy(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/3154")

	p := SetupTest(t)
	t.Cleanup(func() {
		TearDownTest(t, p)
	})

	ackToken := "AckToken-TestRemoveProxyFromThePolicy"

	p.policyData.FleetProxyURL = new(string)
	*p.policyData.FleetProxyURL = p.proxy2.LocalhostURL
	// now that we have fleet and the proxy running, we can add actions which
	// depend on them.
	action, err := fleetservertest.NewActionWithEmptyPolicyChange(
		"actionID-TestRemoveProxyFromThePolicy", p.policyData)
	require.NoError(t, err, "could not generate action with policy")
	p.checkinWithAcker.AddCheckin(
		ackToken,
		0,
		action,
	)
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxy1.LocalhostURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleetNeedsProxyHost,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	// assert the agent is actually connected to fleet.
	check.ConnectedToFleet(t, p.fixture)

	// ensure the agent is communicating through the proxy set in the policy
	if !assert.Eventually(t, func() bool {
		for _, r := range p.proxy2.ProxiedRequests() {
			if strings.Contains(
				r,
				fleetservertest.NewPathCheckin(p.policyData.AgentID)) {
				return true
			}
		}

		return false
	}, 5*time.Minute, 5*time.Second) {
		t.Errorf("did not find requests to the proxy defined in the policy")
	}

	// Assert the proxy is set on the agent
	inspect, err := p.fixture.ExecInspect(context.Background())
	require.NoError(t, err)
	assert.Equal(t, *p.policyData.FleetProxyURL, inspect.Fleet.ProxyURL)

	// remove proxy from the policy
	pp := p.policyData
	want := *pp.FleetProxyURL
	pp.FleetProxyURL = nil
	actionIDRemoveProxyFromPolicy := "actionIDRemoveProxyFromPolicy-actionID-TestRemoveProxyFromThePolicy"
	action, err = fleetservertest.NewActionWithEmptyPolicyChange(
		actionIDRemoveProxyFromPolicy, pp)
	require.NoError(t, err, "could not generate action with policy")
	p.checkinWithAcker.AddCheckin(
		ackToken,
		0,
		action,
	)

	// ensures the agent acked the action sending a policy without proxy
	require.Eventually(t, func() bool {
		return p.checkinWithAcker.Acked(actionIDRemoveProxyFromPolicy)
	},
		30*time.Second, 5*time.Second)
	inspect, err = p.fixture.ExecInspect(context.Background())
	require.NoError(t, err)
	assert.Equal(t, inspect.Fleet.ProxyURL, want)

	// assert, again, the agent is actually connected to fleet.
	check.ConnectedToFleet(t, p.fixture)
}

func (p *ProxyURL) setupFleet(t *testing.T, fleetHost string) {
	agentID := "proxy-url-agent-id"
	policyID := "bedf2f42-a252-40bb-ab2b-8a7e1b874c7a"
	enrollmentToken := "enrollmentToken"
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	p.policyData = fleetservertest.TmplPolicy{
		AgentID:    agentID,
		PolicyID:   policyID,
		FleetHosts: fmt.Sprintf("%q", fleetHost),
		SourceURI:  "http://source.uri",
		CreatedAt:  time.Now().Format(time.RFC3339),
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{
			APIKey: apiKey.String(),
			Hosts:  `"https://my.clould.elstc.co:443"`,
			Type:   "elasticsearch"},
	}

	checkin := fleetservertest.NewCheckinActionsWithAcker()

	fleet := fleetservertest.NewServerWithHandlers(
		apiKey,
		enrollmentToken,
		agentID,
		policyID,
		checkin.ActionsGenerator(),
		checkin.Acker(),
		fleetservertest.WithRequestLog(t.Logf),
	)
	p.fleet = fleet
	p.checkinWithAcker = &checkin

	return
}

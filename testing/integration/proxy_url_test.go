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
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/proxytest"
)

type ProxyURL struct {
	suite.Suite
	fixture *integrationtest.Fixture

	fleet  *fleetservertest.Server
	proxy1 *proxytest.Proxy
	proxy2 *proxytest.Proxy
}

func TestProxyURL(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})

	suite.Run(t, &ProxyURL{})
}

func (p *ProxyURL) SetupTest() {
	fleetHost := "fleet.elastic.co"

	agentVersion := "8.10.0-SNAPSHOT"
	p.setupFleet("http://" + fleetHost)

	p.proxy1 = proxytest.New(p.T(),
		proxytest.WithRewrite(fleetHost, p.fleet.LocalhostURL))
	p.proxy1 = proxytest.New(p.T(),
		proxytest.WithRewrite(fleetHost, p.fleet.LocalhostURL))

	f, err := define.NewFixture(p.T(),
		agentVersion,
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	p.Require().NoError(err, "SetupSuite: NewFixture failed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = f.Prepare(ctx)
	p.Require().NoError(err, "SetupSuite: fixture.Prepare failed")

	p.fixture = f
}

func (p *ProxyURL) TestNoProxyInThePolicy() {
	t := p.T()
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxy1.LocalhostURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleet.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	var status integrationtest.AgentStatusOutput
	if !assert.Eventually(t, func() bool {
		status, err = p.fixture.ExecStatus(context.Background())
		return status.FleetState == int(cproto.State_HEALTHY)
	}, 30*time.Second, 5*time.Second) {
		t.Errorf("want fleet state %d, got %d",
			cproto.State_HEALTHY, status.FleetState)
		t.Logf("agent status: %v", status)
	}
}

func (p *ProxyURL) setupFleet(fleetHost string) {
	agentID := "proxy-url-agent-id"
	actionID := "ActionID"
	policyID := "bedf2f42-a252-40bb-ab2b-8a7e1b874c7a"
	enrollmentToken := "enrollmentToken"
	ackToken := "ackToken"
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	policyData := fleetservertest.TmplPolicy{
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

	fleet := fleetservertest.NewServerWithFakeComponent(
		apiKey,
		enrollmentToken,
		agentID,
		policyID,
		checkin.ActionsGenerator(),
		checkin.Acker(),
		fleetservertest.WithRequestLog(p.T().Logf),
	)
	p.fleet = fleet
	policyData.FleetHosts = fmt.Sprintf("%q", fleet.LocalhostURL)

	// now that we have fleet and the proxy running, we can add actions which
	// depend on them.
	action, err := fleetservertest.NewActionPolicyChange(actionID, policyData)
	require.NoError(p.T(), err, "could not generate action with policy")
	checkin.AddCheckin(
		ackToken,
		0,
		action,
	)

	return
}

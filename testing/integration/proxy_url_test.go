// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
)

type ProxyURL struct {
	suite.Suite
	fixture *integrationtest.Fixture

	fleet *fleetservertest.Server
	stack *define.Info
}

func TestProxyURL(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	suite.Run(t, &ProxyURL{stack: info})
}

func (p *ProxyURL) SetupSuite() {
	// agentVersion := "8.9.0-SNAPSHOT"
	agentID := "proxy-url-agent-id"
	actionID := "ActionID"
	policyID := "bedf2f42-a252-40bb-ab2b-8a7e1b874c7a"
	// enrollmentToken := "enrollmentToken"
	ackToken := "ackToken"
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	// FleetHosts needs to be changed after the server is running, so we can
	// get the port the server is listening on. Therefore, the action generator
	// captures the 'fleetHosts' variable, so it can read the real fleet-server
	// address from it.
	// If you want to predefine an address for the server to listen on, pass
	// WithAddress(addr) to NewServer.
	fleetHosts := "host1"
	var actionsIdx int

	tmpl := fleetservertest.TmplPolicy{
		AckToken: ackToken,
		AgentID:  agentID,
		ActionID: actionID,
		PolicyID: policyID,
		// FleetHosts needs to be changed after the server is running, so we can
		// get the port the server is listening on. Therefore, the action generator
		// captures the 'fleetHosts' variable, so it can read the real fleet-server
		// address from it.
		FleetHosts: `"host1", "host2"`,
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{
			APIKey: apiKey.String(),
			Hosts:  `"https://my.clould.elstc.co:443"`,
			Type:   "elasticsearch"},
	}

	nextAction := func() (fleetservertest.CheckinAction, *fleetservertest.HTTPError) {
		defer func() { actionsIdx++ }()
		tmpl.FleetHosts = fleetHosts

		actions, err := fleetservertest.NewActionPolicyChangeWithFakeComponent(tmpl)
		if err != nil {
			panic(fmt.Sprintf("failed to get new actions: %v", err))
		}

		switch actionsIdx {
		case 0:
			return fleetservertest.CheckinAction{
					AckToken: tmpl.AckToken, Actions: []string{actions}},
				nil
		}

		return fleetservertest.CheckinAction{}, nil
	}

	acker := func(id string) (fleetservertest.AckResponseItem, bool) {
		return fleetservertest.AckResponseItem{
			Status:  http.StatusOK,
			Message: http.StatusText(http.StatusOK),
		}, false
	}

	fleet := fleetservertest.NewServerWithFakeComponent(
		apiKey, agentID, policyID, nextAction, acker,
		fleetservertest.WithRequestLog(log.Printf))
	p.fleet = fleet

	f, err := define.NewFixture(p.T(),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	p.Require().NoError(err, "SetupSuite: NewFixture failed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = f.Prepare(ctx)
	p.Require().NoError(err, "SetupSuite: fixture.Prepare failed")

	p.fixture = f
}

func (p *ProxyURL) Test1() {
	_ = define.Require(p.T(), define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleet.URL,
				EnrollmentToken: "anythingWillDO",
			}})

	fmt.Println("========================================== Agent output ==========================================")
	fmt.Println(out)
	if err != nil {
		fmt.Println("========================================== Agent ERROR ==========================================")
		fmt.Printf("%v\n", err)
	}
}

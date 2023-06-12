// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
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
	// agentID := "proxy-url-agent-id"
	policyID := "bedf2f42-a252-40bb-ab2b-8a7e1b874c7a"
	enrollmentToken := "enrollmentToken"
	ackToken := "ackToken"
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	fleet := fleetservertest.NewServerWithFakeComponent(
		fleetservertest.API{},
		policyID,
		ackToken,
		fleetservertest.Data{
			APIKey:          apiKey,
			EnrollmentToken: enrollmentToken,
			Output: fmt.Sprintf(
				`{"api_key":"%s","hosts":["%s"],"type":"elasticsearch"}`,
				apiKey, "TODO: fix me!"),
		})
	defer fleet.Close()
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
				EnrollmentToken: p.fleet.Data.EnrollmentToken,
			}})

	fmt.Println("========================================== Agent output ==========================================")
	fmt.Println(out)
	if err != nil {
		fmt.Println("========================================== Agent ERROR ==========================================")
		fmt.Printf("%v\n", err)
	}
}

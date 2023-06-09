// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
)

type ProxyURL struct {
	suite.Suite
	f *integrationtest.Fixture

	fleet httptest.Server
}

func (s *ProxyURL) SetupSuite() {
	agentID := "proxy-url-agent-id"
	policyID := "bedf2f42-a252-40bb-ab2b-8a7e1b874c7a"
	enrollmentToken := "enrollmentToken"
	ackToken := "ackToken"
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	fleet := fleetservertest.NewServerWithFakeComponent(
		fleetservertest.API{
			APIKey:          apiKey.Key,
			APIKeyID:        apiKey.ID,
			EnrollmentToken: enrollmentToken,
		},
		agentID, policyID, ackToken)
	defer fleet.Close()

	f, err := define.NewFixture(s.T(),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = f.Prepare(ctx, fakeComponent)
	s.Require().NoError(err)
	s.f = f
}

func TestProxyURL(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: false,
		Sudo:  true,
	})
	suite.Run(t, &ProxyURL{})
}

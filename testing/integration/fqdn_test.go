// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package integration

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestFQDN(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			define.Linux,
		},
		Stack: &define.Stack{},
		Local: false,
	})

	suite.Run(t, &FQDN{requirementsInfo: info})
}

type FQDN struct {
	suite.Suite
	requirementsInfo *define.Info
}

func (s *FQDN) TestFQDN() {
	// Set FQDN on host
	s.setHostFQDN()
	defer s.resetHostFQDN()

	// Create Agent policy

	// Get default Fleet Server URL

	// Enroll agent

	// Verify that agent name is short hostname

	// Verify that hostname in `logs-*` is short hostname

	// Verify that hostname in `metrics-*` is short hostname

	// Update Agent policy to enable FQDN

	// Verify that agent name is FQDN

	// Verify that hostname in `logs-*` is FQDN

	// Verify that hostname in `metrics-*` FQDN

	// Update Agent policy to disable FQDN

	// Verify that agent name is short hostname

	// Verify that hostname in `logs-*` is short hostname

	// Verify that hostname in `metrics-*` is short hostname
}

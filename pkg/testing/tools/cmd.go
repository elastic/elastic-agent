// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func EnrollElasticAgent(fleetUrl string, enrollmentToken string, agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetUrl,
			EnrollmentToken: enrollmentToken,
		},
	}
	return agentFixture.Install(context.Background(), &installOpts)
}

func InstallStandaloneElasticAgent(agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	return agentFixture.Install(context.Background(), &installOpts)
}

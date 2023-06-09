// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

// InstallElasticAgent force install the Elastic Agent through agentFixture.
func InstallElasticAgent(fleetUrl string, enrollmentToken string, agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetUrl,
			EnrollmentToken: enrollmentToken,
		},
	}
	return agentFixture.Install(context.Background(), &installOpts)
}

// InstallStandaloneElasticAgent force install the Elastic Agent through agentFixture.
func InstallStandaloneElasticAgent(agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	return agentFixture.Install(context.Background(), &installOpts)
}

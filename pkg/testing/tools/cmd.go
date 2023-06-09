// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

// InstallAgent force install the Elastic Agent through agentFixture.
func InstallAgent(fleetUrl string, enrollmentToken string, agentFixture *atesting.Fixture) ([]byte, error) {
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

// EnrollWithoutInstall is the same as EnrollElasticAgent, but doesn't install the agent
func EnrollWithoutInstall(fleetURL string, enrollmentToken string, agentFixture *atesting.Fixture) ([]byte, error) {
	enrollOpts := atesting.EnrollOpts{
		URL:             fleetURL,
		EnrollmentToken: enrollmentToken,
	}
	return agentFixture.Enroll(context.Background(), &enrollOpts)
}

// InstallStandaloneAgent force install the Elastic Agent through agentFixture.
func InstallStandaloneAgent(agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	return agentFixture.Install(context.Background(), &installOpts)
}

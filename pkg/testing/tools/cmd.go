// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

// InstallAgent force install the Elastic Agent through agentFixture.
func InstallAgent(installOpts atesting.InstallOpts, agentFixture *atesting.Fixture) ([]byte, error) {
	return agentFixture.Install(context.Background(), &installOpts)
}

// InstallStandaloneAgent force install the Elastic Agent through agentFixture.
func InstallStandaloneAgent(agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	return agentFixture.Install(context.Background(), &installOpts)
}

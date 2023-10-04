// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

// InstallAgent force install the Elastic Agent through agentFixture.
func InstallAgent(ctx context.Context, installOpts atesting.InstallOpts, agentFixture *atesting.Fixture) ([]byte, error) {
	// 2 minute timeout, to ensure that it at least doesn't get stuck.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return agentFixture.Install(ctx, &installOpts)
}

// InstallStandaloneAgent force install the Elastic Agent through agentFixture.
func InstallStandaloneAgent(ctx context.Context, agentFixture *atesting.Fixture) ([]byte, error) {
	// 2 minute timeout, to ensure that it at least doesn't get stuck.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	return agentFixture.Install(ctx, &installOpts)
}

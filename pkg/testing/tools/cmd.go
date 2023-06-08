// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/version"

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

func GetPreviousMinorVersion(v string) (string, error) {
	pv, err := version.ParseVersion(v)
	if err != nil {
		return "", fmt.Errorf("error parsing version [%s]: %w", v, err)
	}

	major := pv.Major()
	minor := pv.Minor()

	if minor > 0 {
		// We have at least one previous minor version in the current
		// major version series
		return fmt.Sprintf("%d.%d.%d", major, minor-1, 0), nil
	}

	// We are at the first minor of the current major version series. To
	// figure out the previous minor, we need to rely on knowledge of
	// the release versions from the past major series'.
	switch major {
	case 8:
		return "7.17.10", nil
	}

	return "", fmt.Errorf("unable to determine previous minor version for [%s]", v)
}

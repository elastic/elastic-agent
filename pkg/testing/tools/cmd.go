// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"fmt"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func EnrollElasticAgent(fleetUrl string, enrollmentToken string, agentFixture *atesting.Fixture) ([]byte, error) {
	args := []string{
		"install",
		"--non-interactive",
		fmt.Sprintf("--url=%s", fleetUrl),
		fmt.Sprintf("--enrollment-token=%s", enrollmentToken),
	}
	return agentFixture.Exec(context.Background(), args)
}

func UninstallAgent(agentFixture *atesting.Fixture) ([]byte, error) {
	args := []string{
		"uninstall",
		"-f",
	}
	return agentFixture.Exec(context.Background(), args)
}

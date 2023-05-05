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

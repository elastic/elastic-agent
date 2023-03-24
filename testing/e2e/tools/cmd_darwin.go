//go:build darwin
// +build darwin

package tools

import (
	"fmt"
	"os/exec"
	"testing"
)

func EnrollElasticAgent(t *testing.T, fleetUrl string, enrollmentToken string, version string) error {
	cmd := exec.Command(fmt.Sprintf("elastic-agent-%s-darwin-aarch64/elastic-agent", version), //nolint:gosec //TODO: exclude from binary
		"install", "--non-interactive", fmt.Sprintf("--url=%s", fleetUrl), fmt.Sprintf("--enrollment-token=%s", enrollmentToken))

	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Errorf(string(out))
	}

	return err
}

func UninstallAgent(t *testing.T) error {
	cmd := exec.Command("elastic-agent",
		"uninstall",
		"-f")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Errorf(string(out))
	}

	return err
}

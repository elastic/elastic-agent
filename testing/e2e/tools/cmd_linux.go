// go:build linux
//go:build linux
// +build linux

package tools

import (
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"testing"

	"github.com/google/uuid"
)

func EnrollElasticAgent(t *testing.T, fleetUrl string, enrollmentToken string, agentPath string) error {
	t.Log("Enrolling elastic agent ...")

	cmd := exec.Command(agentPath, //nolint:gosec //TODO: exclude from binary
		"install", "--non-interactive", fmt.Sprintf("--url=%s", fleetUrl), fmt.Sprintf("--enrollment-token=%s", enrollmentToken))

	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Error(err)
	}
	t.Log(string(out))

	return err
}

func InstallElasticAgentStandalone(esConfig *ESConfig, version string) error {
	dat, err := os.ReadFile("elastic-agent.yml.tpl")
	if err != nil {
		panic(err)
	}
	tmpl := template.New("ea-template")
	tmpl, err = tmpl.Parse(string(dat))
	if err != nil {
		return err
	}

	err = tmpl.Execute(os.Stdout, struct {
		Es ESConfig
		Id string
	}{*esConfig, uuid.New().String()})

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

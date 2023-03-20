//go:build linux
// +build linux

package tools

import (
	"fmt"
	"html/template"
	"os"
	"os/exec"

	"github.com/google/uuid"
	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega/gexec"
)

func EnrollElasticAgent(fleetUrl string, enrollmentToken string, version string) (*gexec.Session, error) {
	command := exec.Command(fmt.Sprintf("elastic-agent-%s-linux-arm64/elastic-agent", version), //nolint:gosec //TODO: exclude from binary
		"install",
		"--non-interactive",
		fmt.Sprintf("--url=%s", fleetUrl),
		fmt.Sprintf("--enrollment-token=%s", enrollmentToken))

	return gexec.Start(command, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)
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

func UninstallAgent() (*gexec.Session, error) {
	command := exec.Command("elastic-agent",
		"uninstall",
		"-f")
	return gexec.Start(command, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)

}

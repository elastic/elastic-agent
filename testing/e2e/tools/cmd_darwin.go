//go:build darwin
// +build darwin

package tools

import (
	"fmt"
	"os/exec"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega/gexec"
)

func EnrollElasticAgent(fleetUrl string, enrollmentToken string, version string) (*gexec.Session, error) {
	command := exec.Command(fmt.Sprintf("elastic-agent-%s-darwin-aarch64/elastic-agent", version), //nolint:gosec //TODO: exclude from binary
		"install", "--non-interactive", fmt.Sprintf("--url=%s", fleetUrl), fmt.Sprintf("--enrollment-token=%s", enrollmentToken))

	return gexec.Start(command, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)

}

func UninstallAgent() (*gexec.Session, error) {
	command := exec.Command("elastic-agent",
		"uninstall",
		"-f")
	return gexec.Start(command, ginkgo.GinkgoWriter, ginkgo.GinkgoWriter)

}

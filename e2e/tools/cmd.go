package tools

import (
	"fmt"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega/gexec"
)

func EnrollElasticAgent(fleetUrl string, enrollmentToken string) (*gexec.Session, error) {
	command := exec.Command("elastic-agent-8.6.2-linux-arm64/elastic-agent",
		"install",
		"--non-interactive",
		fmt.Sprintf("--url=%s", fleetUrl),
		fmt.Sprintf("--enrollment-token=%s", enrollmentToken))

	return gexec.Start(command, GinkgoWriter, GinkgoWriter)

}

func UninstallAgent() (*gexec.Session, error) {
	command := exec.Command("elastic-agent",
		"uninstall",
		"-f")
	return gexec.Start(command, GinkgoWriter, GinkgoWriter)

}

package tools

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func DownloadElasticAgent(version string) error {
	log.Info("Installing Elastic Agent...")
	dirToInstall, err := os.Getwd()
	if err != nil {
		return err
	}
	fileName := fmt.Sprintf("elastic-agent-%s-darwin-x86_64.tar.gz", version)
	agentTarPath := fmt.Sprintf("%s/%s", dirToInstall, fileName)
	err = DownloadFile(fmt.Sprintf(agentTarPath),
		"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.6.1-darwin-x86_64.tar.gz")

	if err != nil {
		return err
	}
	out, err := exec.Command("tar", "-xvf", agentTarPath).Output()
	log.Info(out)

	// TODO install elastic-agent with enrollment token
	return err
}

func DownloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

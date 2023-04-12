//go:build linux || darwin
// +build linux darwin

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
	dirToInstall, err := os.Getwd()
	if err != nil {
		return err
	}

	fileName, destFileName, err := tarName(version)
	if err != nil {
		return err
	}
	agentTarPath := fmt.Sprintf("%s/%s", dirToInstall, destFileName)
	err = DownloadFile(agentTarPath, fmt.Sprintf("https://artifacts.elastic.co/downloads/beats/elastic-agent/%s", fileName))

	if err != nil {
		return err
	}
	_, err = exec.Command("tar", "-xvf", agentTarPath).Output()

	return err
}

func DownloadFile(filepath string, url string) error {
	log.Info("Downloading Elastic Agent...")
	log.Info(url)

	resp, err := http.Get(url) //nolint:gosec,noctx //TODO: exclude from binary, no user input
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

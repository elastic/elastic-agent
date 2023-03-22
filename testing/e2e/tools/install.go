//go:build linux
// +build linux

package tools

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func DownloadElasticAgent(version string) error {
	dirToInstall, err := os.Getwd()
	if err != nil {
		return err
	}

	fileName, destFileName := tarName(version)
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

func tarName(version string) (string, string) {
	fileName := fmt.Sprintf("elastic-agent-%s-linux-arm64.tar.gz", version)
	destFileName := fmt.Sprintf("%s%s", "elastic-agent", filepath.Ext(fileName))
	return fileName, destFileName
}

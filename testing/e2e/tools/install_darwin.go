//go:build darwin
// +build darwin

package tools

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/mholt/archiver/v3"

	log "github.com/sirupsen/logrus"
)

func DownloadElasticAgent(version string) error {
	dirToInstall, err := os.Getwd()
	if err != nil {
		return err
	}

	fileName, destFileName := tarName(version)
	agentTarPath := fmt.Sprintf("%s/%s", dirToInstall, destFileName)
	err = downloadFile(agentTarPath, fmt.Sprintf("https://artifacts.elastic.co/downloads/beats/elastic-agent/%s", fileName))

	if err != nil {
		return err
	}
	_, err = exec.Command("tar", "-xvf", agentTarPath).Output()

	return err
}

func downloadFile(filepath string, url string) error {
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

func UnpackTar(version string) error {
	// TODO: slow in containers
	_, fileName := tarName(version)
	return archiver.Unarchive(fileName, ".")
}

func tarName(version string) (string, string) {
	fileName := fmt.Sprintf("elastic-agent-%s-darwin-aarch64.tar.gz", version)
	destFileName := fmt.Sprintf("%s%s", "elastic-agent", filepath.Ext(fileName))
	return fileName, destFileName
}

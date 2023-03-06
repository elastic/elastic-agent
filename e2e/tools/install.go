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
	fileName := fmt.Sprintf("elastic-agent-%s-linux-arm64.tar.gz", version)
	destFileName := fmt.Sprintf("%s%s", "elastic-agent", filepath.Ext(fileName))
	agentTarPath := fmt.Sprintf("%s/%s", dirToInstall, destFileName)
	err = DownloadFile(agentTarPath, fmt.Sprintf("https://artifacts.elastic.co/downloads/beats/elastic-agent/%s", fileName))

	if err != nil {
		return err
	}
	out, err := exec.Command("tar", "-xvf", agentTarPath).Output()
	log.Info(out)

	return err
}

func DownloadFile(filepath string, url string) error {
	log.Info("Downloading Elastic Agent...")
	log.Info(url)

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
	log.Info("123123123")
	return err
}

func UnpackTar(version string) error {
	//TODO too slow
	return archiver.Unarchive(fmt.Sprintf("elastic-agent-%s-linux-arm64.tar", version), ".")
}

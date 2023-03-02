package tools

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/mholt/archiver/v3"

	log "github.com/sirupsen/logrus"
)

func DownloadElasticAgent(version string) error {
	log.Info("Installing Elastic Agent...")
	dirToInstall, err := os.Getwd()
	if err != nil {
		return err
	}
	fileName := fmt.Sprintf("elastic-agent-%s-linux-arm64.tar", version)
	agentTarPath := fmt.Sprintf("%s/%s", dirToInstall, fileName)
	err = DownloadFile(agentTarPath, fmt.Sprintf("https://artifacts.elastic.co/downloads/beats/elastic-agent/%s", fileName))

	if err != nil {
		return err
	}
	out, err := exec.Command("tar", "-xvf", agentTarPath).Output()
	log.Info(out)

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

func UnpackTar(version string) error {
	//TODO too slow
	return archiver.Unarchive(fmt.Sprintf("elastic-agent-%s-linux-arm64.tar", version), ".")
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

func TestInstall(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			define.OS{Type: "darwin"},
		},

		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	binPath := info.Fixture.ExecutablePath

	suite.Run(t, newInstallTestSuite(binPath))
}

func newInstallTestSuite(binPath string) *InstallTestSuite {
	i := new(InstallTestSuite)
	i.binPath = binPath

	return i
}

type InstallTestSuite struct {
	suite.Suite
	binPath string
}

func (i *InstallTestSuite) TestInstallWithoutBasePath() {
	// Check that default base path is clean
	basePath := "/Library"
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	_, err := os.Stat(topPath)
	i.Require().True(os.IsNotExist(err))

	// Run elastic-agent install.  We use --force to prevent interactive
	// execution.
	cmd := exec.Command(i.binPath, "--force")
	err := cmd.Run()
	i.Require().NoError(err)

	// Check that Agent was installed in default base path
	i.checkInstallSuccess(topPath)
}

func (i *InstallTestSuite) TestInstallWithBasePath() {
	tmpDir := os.TempDir()
	randomBasePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))
	defer os.RemoveAll(randomBasePath)

	// Run elastic-agent install.  We use --force to prevent interactive
	// execution.
	cmd := exec.Command(i.binPath, "--base-path", randomBasePath, "--force")
	err := cmd.Run()
	i.Require().NoError(err)

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(randomBasePath, "Elastic", "Agent")
	i.checkInstallSuccess(topPath)
}

func (i *InstallTestSuite) checkInstallSuccess(topPath string) {
	_, err := os.Stat(topPath)
	i.Require().NoError(err)

	// Check that a few expected installed files are present
	installedBinPath := filepath.Join(topPath, "elastic-agent")
	installedDataPath := filepath.Join(topPath, "data")
	installMarkerPath := filepath.Join(topPath, ".installed")

	_, err = os.Stat(installedBinPath)
	i.Require().NoError(err)
	_, err = os.Stat(installedDataPath)
	i.Require().NoError(err)
	_, err = os.Stat(installMarkerPath)
	i.Require().NoError(err)
}

func randStr(length int) string {
	rand.Seed(time.Now().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	runes := make([]rune, length)
	for i := range runes {
		runes[i] = letters[rand.Intn(len(letters))]
	}

	return string(runes)
}

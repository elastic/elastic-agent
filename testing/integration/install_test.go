// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestInstall(t *testing.T) {
	define.Require(t, define.Requirements{
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,

		// Since this test sets the location on the
		// filesystem where Elastic Agent will be
		// installed, it's probably safest not to run
		// it along with other tests.
		Isolate: true,
	})

	// Get path to Elastic Agent executable
	fixture := define.NewFixture(t)

	suite.Run(t, newInstallTestSuite(fixture))
}

func newInstallTestSuite(fixture *atesting.Fixture) *InstallTestSuite {
	i := new(InstallTestSuite)
	i.fixture = fixture

	return i
}

type InstallTestSuite struct {
	suite.Suite
	fixture *atesting.Fixture
}

func (i *InstallTestSuite) TestInstallWithoutBasePath() {
	// Check that default base path is clean
	var defaultBasePath string
	switch runtime.GOOS {
	case "darwin":
		defaultBasePath = `/Library`
	case "linux":
		defaultBasePath = `/opt`
	case "windows":
		defaultBasePath = `C:\Program Files`
	}

	topPath := filepath.Join(defaultBasePath, "Elastic", "Agent")
	_, err := os.Stat(topPath)
	i.Require().True(os.IsNotExist(err))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	_, err = i.fixture.Install(context.Background(), &atesting.InstallOpts{Force: true})
	i.Require().NoError(err)

	// Check that Agent was installed in default base path
	i.checkInstallSuccess(topPath)
}

func (i *InstallTestSuite) TestInstallWithBasePath() {
	const basePathFlag = "--base-path"

	// The `--base-path` flag is defined for the `elastic-agent install` CLI sub-command BUT
	// it is hidden (see https://github.com/elastic/elastic-agent/pull/2592).  So we validate
	// here that the usage text for the `install` sub-command does NOT mention the `--base-path`
	// flag in it.
	output, err := i.fixture.Exec(context.Background(), []string{"help", "install"})
	i.Require().NoError(err)
	require.NotContains(i.T(), string(output), basePathFlag)

	// Set up random temporary directory to serve as base path for Elastic Agent
	// installation.
	tmpDir := os.TempDir()
	randomBasePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))
	defer os.RemoveAll(randomBasePath)

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	_, err = i.fixture.Install(context.Background(), &atesting.InstallOpts{
		BasePath: randomBasePath,
		Force:    true,
	})
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

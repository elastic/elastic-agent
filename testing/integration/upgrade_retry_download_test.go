// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/release"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/testing/tools"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestElasticAgentUpgradeRetryDownload(t *testing.T) {
	info := define.Require(t, define.Requirements{
		// FIXME: only for testing on remote VM
		Local:   true, // requires Agent installation
		Isolate: true, // requires Agent installation and modifying /etc/hosts
		Sudo:    true, // requires Agent installation and modifying /etc/hosts
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		}, // modifying /etc/hosts
	})

	currentVersion := define.Version()
	previousVersion, err := getPreviousMinorVersion(currentVersion)
	require.NoError(t, err)

	suite.Run(t, newUpgradeElasticAgentStandaloneRetryDownloadTestSuite(info, currentVersion, previousVersion))
}

type UpgradeElasticAgentStandaloneRetryDownload struct {
	suite.Suite

	requirementsInfo  *define.Info
	agentStartVersion string
	agentEndVersion   string
	agentFixture      *atesting.Fixture

	isEtcHostsModified bool
}

type versionInfo struct {
	Version string `yaml:"version"`
	Commit  string `yaml:"commit"`
}

type versionOutput struct {
	Binary versionInfo `yaml:"binary"`
	Daemon versionInfo `yaml:"daemon"`
}

func newUpgradeElasticAgentStandaloneRetryDownloadTestSuite(info *define.Info, startVersion, endVersion string) *UpgradeElasticAgentStandaloneRetryDownload {
	return &UpgradeElasticAgentStandaloneRetryDownload{
		requirementsInfo:  info,
		agentStartVersion: startVersion,
		agentEndVersion:   endVersion,
	}
}

// Before suite
func (s *UpgradeElasticAgentStandaloneRetryDownload) SetupSuite() {
	agentFixture, err := define.NewFixture(
		s.T(),
	)
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = agentFixture.Prepare(ctx)
	s.Require().NoError(err, "error preparing agent fixture")
	s.agentFixture = agentFixture
}

func (s *UpgradeElasticAgentStandaloneRetryDownload) TestUpgradeStandaloneElasticAgentRetryDownload() {
	s.T().Log("Install the built Agent")
	output, err := tools.InstallStandaloneElasticAgent(s.agentFixture)
	s.T().Log(string(output))
	s.Require().NoError(err)

	s.T().Log("Ensure the correct version is running")
	var version *versionOutput
	s.Eventually(func() bool {
		version, err = s.getVersion()
		if err != nil {
			return false
		}

		s.Require().Equal(release.Version(), version.Binary.Version)
		s.Require().Equal(release.Version(), version.Daemon.Version)
		return true
	}, 1*time.Minute, 1*time.Second)

	s.T().Log("Modify /etc/hosts to simulate transient network error")
	cmd := exec.Command("sed",
		"-i.bak",
		"s/localhost/localhost artifacts.elastic.co artifacts-api.elastic.co/g",
		"/etc/hosts",
	)
	s.T().Log("/etc/hosts modify command: ", cmd.String())

	output, err = cmd.CombinedOutput()
	if err != nil {
		s.T().Log(string(output))
	}
	s.Require().NoError(err)

	s.isEtcHostsModified = true
	defer s.restoreEtcHosts()

	s.T().Log("Start the Agent upgrade")
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)

		// elastic-agent upgrade 8.8.0
		cmd := exec.Command("elastic-agent",
			"upgrade",
			"8.8.0",
		)
		s.T().Log("Upgrade command: ", cmd.String())

		output, err := cmd.CombinedOutput()
		if err != nil {
			s.T().Log(string(output))
		}

		wg.Done()
		s.Require().NoError(err)
	}()

	s.T().Log("Check Agent logs for at least two retry messages")
	s.Eventually(func() bool {
		agentDirName := fmt.Sprintf("elastic-agent-%s", release.TrimCommit(version.Daemon.Commit))
		logsPath := filepath.Join(paths.DefaultBasePath, "Elastic", "Agent", "data", agentDirName, "logs")

		cmd := exec.Command("grep",
			"download.*retrying",
			"--recursive",
			"--include", "*.ndjson",
			logsPath,
		)
		s.T().Log("Find logs command: ", cmd.String())

		// We don't check the error as grep will return non-zero exit code when
		// it doesn't find any matches, which could happen the first couple of
		// times it searches the Elastic Agent logs.
		output, _ := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		outputLines := strings.Split(outputStr, "\n")
		s.T().Log(outputLines)
		s.T().Log("Num lines: ", len(outputLines)) // FIXME
		return len(outputLines) >= 2
	}, 1*time.Minute, 10*time.Second)

	s.T().Log("Restore /etc/hosts so upgrade can proceed")
	s.restoreEtcHosts()

	// Wait for upgrade command to finish executing
	wg.Wait()

	s.T().Log("Check Agent version to ensure upgrade is successful")
	version, err = s.getVersion()
	s.Require().NoError(err)
	s.Require().Equal("8.8.0", version.Binary.Version)
	s.Require().Equal("8.8.0", version.Daemon.Version)
}

func (s *UpgradeElasticAgentStandaloneRetryDownload) restoreEtcHosts() {
	if !s.isEtcHostsModified {
		return
	}

	cmd := exec.Command("mv",
		"/etc/hosts.bak",
		"/etc/hosts",
	)
	err := cmd.Run()
	s.Require().NoError(err)
	s.isEtcHostsModified = false
}

func (s *UpgradeElasticAgentStandaloneRetryDownload) getVersion() (*versionOutput, error) {
	cmd := exec.Command("elastic-agent",
		"version",
		"--yaml",
	)
	s.T().Log("Version check command: ", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.T().Log(string(output))
		return nil, err
	}

	var version versionOutput

	err = yaml.Unmarshal(output, &version)
	if err != nil {
		return nil, err
	}

	return &version, nil
}

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

	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

func TestElasticAgentUpgradeRetryDownload(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Local:   false, // requires Agent installation
		Isolate: false,
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
	ctx := context.Background()

	s.T().Log("Install the built Agent")
	output, err := tools.InstallStandaloneElasticAgent(s.agentFixture)
	s.T().Log(string(output))
	s.Require().NoError(err)

	s.T().Log("Ensure the correct version is running")
	version, err := s.getVersion(ctx)
	s.Require().NoError(err)

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

	// Ensure that /etc/hosts is modified
	s.Eventually(func() bool {
		cmd := exec.Command("grep",
			"artifacts",
			"/etc/hosts",
		)
		s.T().Log("Check /etc/hosts command: ", cmd.String())

		// We don't check the error as grep will return non-zero exit code when
		// it doesn't find any matches, which could happen the first couple of
		// times it searches /etc/hosts.
		output, _ := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		return outputStr != ""
	}, 10*time.Second, 1*time.Second)

	s.isEtcHostsModified = true
	defer s.restoreEtcHosts()

	s.T().Log("Start the Agent upgrade")
	const targetVersion = "8.8.0"
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)

		err := s.upgradeAgent(ctx, targetVersion)

		wg.Done()
		s.Require().NoError(err)
	}()

	s.T().Log("Check Agent logs for at least two retry messages")
	agentDirName := fmt.Sprintf("elastic-agent-%s", release.TrimCommit(version.Daemon.Commit))
	logsPath := filepath.Join(paths.DefaultBasePath, "Elastic", "Agent", "data", agentDirName, "logs")
	s.Eventually(func() bool {
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
		s.T().Log("Number of retry messages: ", len(outputLines))
		return len(outputLines) >= 2
	}, 2*time.Minute, 20*time.Second)

	s.T().Log("Restore /etc/hosts so upgrade can proceed")
	s.restoreEtcHosts()

	// Wait for upgrade command to finish executing
	s.T().Log("Waiting for upgrade to finish")
	wg.Wait()

	s.T().Log("Check Agent version to ensure upgrade is successful")
	version, err = s.getVersion(ctx)
	s.Require().NoError(err)
	s.Require().Equal(targetVersion, version.Binary.Version)
	s.Require().Equal(targetVersion, version.Daemon.Version)
}

func (s *UpgradeElasticAgentStandaloneRetryDownload) getVersion(ctx context.Context) (*versionOutput, error) {
	var version versionOutput
	var err error

	s.Eventually(func() bool {
		args := []string{"version", "--yaml"}
		var output []byte
		output, err = s.agentFixture.Exec(ctx, args)

		if err != nil {
			s.T().Log(string(output))
			return false
		}

		err = yaml.Unmarshal(output, &version)
		if err != nil {
			return false
		}

		return true
	}, 1*time.Minute, 1*time.Second)

	return &version, err
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

func (s *UpgradeElasticAgentStandaloneRetryDownload) upgradeAgent(ctx context.Context, version string) error {
	args := []string{"upgrade", version}
	output, err := s.agentFixture.Exec(ctx, args)
	if err != nil {
		s.T().Log("Upgrade command output after error: ", string(output))
		return err
	}

	return nil
}

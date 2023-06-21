// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"golang.org/x/crypto/ssh"
	"path/filepath"
	"time"
)

// WindowsRunner is a handler for running tests on Windows
type WindowsRunner struct{}

// Prepare the test
func (WindowsRunner) Prepare(ctx context.Context, c *ssh.Client, logger Logger, arch string, goVersion string, repoArchive string, buildPath string) error {
	// install chocolatey
	logger.Logf("Installing chocolatey")
	chocoInstall := `"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"`
	stdOut, errOut, err := sshRunPowershell(ctx, c, chocoInstall)
	if err != nil {
		return fmt.Errorf("failed to install chocolatey: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// install make
	logger.Logf("Installing make")
	stdOut, errOut, err = sshRunCommand(ctx, c, "%ALLUSERSPROFILE%\\chocolatey\\bin\\choco", []string{"install", "-y", "make"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install golang: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// install golang
	goVersion = "1.19.9"
	logger.Logf("Installing golang %s (%s)", goVersion, arch)
	stdOut, errOut, err = sshRunCommand(ctx, c, "%ALLUSERSPROFILE%\\chocolatey\\bin\\choco", []string{"install", "-y", "golang", fmt.Sprintf("--version=%s", goVersion)}, nil)
	if err != nil {
		return fmt.Errorf("failed to install golang: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// setup the environment variables for golang
	envSetup := `"[System.Environment]::SetEnvironmentVariable('GOPATH', $env:HOME+'\go'); [System.Environment]::SetEnvironmentVariable('PATH',$env:HOME+'\go\bin;'+$env:PATH)"`
	stdOut, errOut, err = sshRunPowershell(ctx, c, envSetup)
	if err != nil {
		return fmt.Errorf("failed to setup environment variables: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "%ALLUSERSPROFILE%\\chocolatey\\bin\\RefreshEnv.cmd", nil, nil)
	if err != nil {
		return fmt.Errorf("failed to refresh environment variables: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// copy the archive and extract it on the host (tar exists and can extract zip on windows)
	logger.Logf("Copying repo")
	destRepoName := filepath.Base(repoArchive)
	err = sshSCP(c, repoArchive, destRepoName)
	if err != nil {
		return fmt.Errorf("failed to SCP repo archive %s: %w", repoArchive, err)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "mkdir", []string{"agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to mkdir agent: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "tar", []string{"-xf", destRepoName, "-C", "agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to unzip %s to agent directory: %w (stdout: %s, stderr: %s)", destRepoName, err, stdOut, errOut)
	}

	// install mage and prepare for testing
	logger.Logf("Running make mage and prepareOnRemote")
	stdOut, errOut, err = sshRunCommand(ctx, c, "cd", []string{"agent", "&&", "make", "mage", "&&", "mage", "integration:prepareOnRemote"}, nil)
	if err != nil {
		logger.Logf("Waiting for 30 minutes")
		<-time.After(30 * time.Minute)
		return fmt.Errorf("failed to to perform make mage and prepareOnRemote: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// place the build for the agent on the host
	logger.Logf("Copying agent build %s", filepath.Base(buildPath))
	err = sshSCP(c, buildPath, filepath.Base(buildPath))
	if err != nil {
		return fmt.Errorf("failed to SCP build %s: %w", filepath.Base(buildPath), err)
	}
	insideAgentDir := filepath.Join("agent", buildPath)
	stdOut, errOut, err = sshRunCommand(ctx, c, "mkdir", []string{filepath.Dir(insideAgentDir)}, nil)
	if err != nil {
		return fmt.Errorf("failed to create %s directory: %w (stdout: %s, stderr: %s)", filepath.Dir(insideAgentDir), err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "move", []string{filepath.Base(buildPath), insideAgentDir}, nil)
	if err != nil {
		return fmt.Errorf("failed to move %s to %s: %w (stdout: %s, stderr: %s)", filepath.Base(buildPath), insideAgentDir, err, stdOut, errOut)
	}

	logger.Logf("Waiting for 30 minutes")
	<-time.After(30 * time.Minute)

	return nil
}

// Run the test
func (WindowsRunner) Run(ctx context.Context, c *ssh.Client, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error) {
	return OSRunnerResult{}, fmt.Errorf("not done")
}

func sshRunPowershell(ctx context.Context, c *ssh.Client, cmd string) ([]byte, []byte, error) {
	return sshRunCommand(ctx, c, "powershell.exe", []string{
		"-NoProfile",
		"-InputFormat", "None",
		"-ExecutionPolicy", "Bypass",
		"-Command", cmd,
	}, nil)
}

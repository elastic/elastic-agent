// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/magefile/mage/mg"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// WindowsRunner is a handler for running tests on Windows
type WindowsRunner struct{}

// Prepare the test
func (WindowsRunner) Prepare(ctx context.Context, c SSHClient, logger Logger, arch string, goVersion string, repoArchive string, buildPath string) error {
	// install chocolatey
	logger.Logf("Installing chocolatey")
	chocoInstall := `"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"`
	stdOut, errOut, err := sshRunPowershell(ctx, c, chocoInstall)
	if err != nil {
		return fmt.Errorf("failed to install chocolatey: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// reconnect to get updated environment variables (1 minute as it should be quick to reconnect)
	err = c.ReconnectWithTimeout(ctx, 1*time.Minute)

	// install curl
	logger.Logf("Installing curl")
	stdOut, errOut, err = c.Exec(ctx, "choco", []string{"install", "-y", "curl"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install curl: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// install make
	logger.Logf("Installing make")
	stdOut, errOut, err = c.Exec(ctx, "choco", []string{"install", "-y", "make"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install make: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// install golang (doesn't use choco, because sometimes it doesn't have the required version)
	logger.Logf("Installing golang %s (%s)", goVersion, arch)
	downloadURL := fmt.Sprintf("https://go.dev/dl/go%s.windows-%s.msi", goVersion, arch)
	filename := path.Base(downloadURL)
	stdOut, errOut, err = c.Exec(ctx, "curl", []string{"-Ls", downloadURL, "--output", filename}, nil)
	if err != nil {
		return fmt.Errorf("failed to download go from %s with curl: %w (stdout: %s, stderr: %s)", downloadURL, err, stdOut, errOut)
	}
	stdOut, errOut, err = c.Exec(ctx, "msiexec", []string{"/i", filename, "/qn"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install go: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// reconnect to get updated environment variables (1 minute as it should be quick to reconnect)
	err = c.ReconnectWithTimeout(ctx, 1*time.Minute)

	// copy the archive and extract it on the host (tar exists and can extract zip on windows)
	logger.Logf("Copying repo")
	destRepoName := filepath.Base(repoArchive)
	err = c.Copy(repoArchive, destRepoName)
	if err != nil {
		return fmt.Errorf("failed to SCP repo archive %s: %w", repoArchive, err)
	}
	stdOut, errOut, err = c.Exec(ctx, "mkdir", []string{"agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to mkdir agent: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = c.Exec(ctx, "tar", []string{"-xf", destRepoName, "-C", "agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to unzip %s to agent directory: %w (stdout: %s, stderr: %s)", destRepoName, err, stdOut, errOut)
	}

	// install mage and prepare for testing
	logger.Logf("Running make mage and prepareOnRemote")
	stdOut, errOut, err = c.Exec(ctx, "cd", []string{"agent", "&&", "make", "mage", "&&", "mage", "integration:prepareOnRemote"}, nil)
	if err != nil {
		return fmt.Errorf("failed to to perform make mage and prepareOnRemote: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// place the build for the agent on the host
	logger.Logf("Copying agent build %s", filepath.Base(buildPath))
	err = c.Copy(buildPath, filepath.Base(buildPath))
	if err != nil {
		return fmt.Errorf("failed to SCP build %s: %w", filepath.Base(buildPath), err)
	}
	insideAgentDir := filepath.Join("agent", buildPath)
	stdOut, errOut, err = c.Exec(ctx, "mkdir", []string{toWindowsPath(filepath.Dir(insideAgentDir))}, nil)
	if err != nil {
		return fmt.Errorf("failed to create %s directory: %w (stdout: %s, stderr: %s)", toWindowsPath(filepath.Dir(insideAgentDir)), err, stdOut, errOut)
	}
	stdOut, errOut, err = c.Exec(ctx, "move", []string{filepath.Base(buildPath), toWindowsPath(insideAgentDir)}, nil)
	if err != nil {
		return fmt.Errorf("failed to move %s to %s: %w (stdout: %s, stderr: %s)", filepath.Base(buildPath), toWindowsPath(insideAgentDir), err, stdOut, errOut)
	}

	return nil
}

// Run the test
func (WindowsRunner) Run(ctx context.Context, verbose bool, c SSHClient, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error) {
	var tests []string
	for _, pkg := range batch.Tests {
		for _, test := range pkg.Tests {
			tests = append(tests, fmt.Sprintf("%s:%s", pkg.Name, test))
		}
	}
	var sudoTests []string
	for _, pkg := range batch.SudoTests {
		for _, test := range pkg.Tests {
			sudoTests = append(sudoTests, fmt.Sprintf("%s:%s", pkg.Name, test))
		}
	}

	var result OSRunnerResult
	if len(tests) > 0 {
		logger.Logf("Starting tests")
		execTest := strings.NewReader(toPowershellScript(agentVersion, prefix, mg.Verbose(), tests, env))
		session, err := c.NewSession()
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("failed to start session: %w", err)
		}

		session.Stdout = newPrefixOutput(logger, "Test output (stdout): ")
		session.Stderr = newPrefixOutput(logger, "Test output (stderr): ")
		session.Stdin = execTest
		// allowed to fail because tests might fail
		_ = session.Run("powershell -noprofile -noninteractive -")
		_ = session.Close()

		// fetch the contents for each package
		for _, pkg := range batch.Tests {
			resultPkg, err := getWindowsRunnerPackageResult(ctx, c, pkg, prefix)
			if err != nil {
				return OSRunnerResult{}, err
			}
			result.Packages = append(result.Packages, resultPkg)
		}
	}

	if len(sudoTests) > 0 {
		prefix := fmt.Sprintf("%s-sudo", prefix)
		logger.Logf("Starting sudo tests")
		execTest := strings.NewReader(toPowershellScript(agentVersion, prefix, mg.Verbose(), sudoTests, env))

		session, err := c.NewSession()
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("failed to start session: %w", err)
		}

		session.Stdout = newPrefixOutput(logger, "Test output (sudo) (stdout): ")
		session.Stderr = newPrefixOutput(logger, "Test output (sudo) (stderr): ")
		session.Stdin = execTest
		// allowed to fail because tests might fail
		_ = session.Run("powershell -noprofile -noninteractive -")
		_ = session.Close()

		// fetch the contents for each package
		for _, pkg := range batch.SudoTests {
			resultPkg, err := getWindowsRunnerPackageResult(ctx, c, pkg, prefix)
			if err != nil {
				return OSRunnerResult{}, err
			}
			result.SudoPackages = append(result.SudoPackages, resultPkg)
		}
	}
	return result, nil
}

func sshRunPowershell(ctx context.Context, c SSHClient, cmd string) ([]byte, []byte, error) {
	return c.Exec(ctx, "powershell", []string{
		"-NoProfile",
		"-InputFormat", "None",
		"-ExecutionPolicy", "Bypass",
		"-Command", cmd,
	}, nil)
}

func toPowershellScript(agentVersion string, prefix string, verbose bool, tests []string, env map[string]string) string {
	var sb strings.Builder
	for k, v := range env {
		sb.WriteString("$env:")
		sb.WriteString(k)
		sb.WriteString("=\"")
		sb.WriteString(v)
		sb.WriteString("\"\n")
	}
	sb.WriteString("$env:AGENT_VERSION=\"")
	sb.WriteString(agentVersion)
	sb.WriteString("\"\n")
	sb.WriteString("$env:TEST_DEFINE_PREFIX=\"")
	sb.WriteString(prefix)
	sb.WriteString("\"\n")
	sb.WriteString("$env:TEST_DEFINE_TESTS=\"")
	sb.WriteString(strings.Join(tests, ","))
	sb.WriteString("\"\n")
	sb.WriteString("cd agent\n")
	sb.WriteString("mage ")
	if verbose {
		sb.WriteString("-v ")
	}
	sb.WriteString("integration:testOnRemote\n")
	return sb.String()
}

func toWindowsPath(path string) string {
	return strings.ReplaceAll(path, "/", "\\")
}

func getWindowsRunnerPackageResult(ctx context.Context, c SSHClient, pkg define.BatchPackageTests, prefix string) (OSRunnerPackageResult, error) {
	var err error
	var resultPkg OSRunnerPackageResult
	resultPkg.Name = pkg.Name
	outputPath := fmt.Sprintf("%%home%%\\agent\\build\\TEST-go-remote-%s.%s", prefix, filepath.Base(pkg.Name))
	resultPkg.Output, err = c.GetFileContents(ctx, outputPath+".out", WithContentFetchCommand("type"))
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.out", outputPath)
	}
	resultPkg.JSONOutput, err = c.GetFileContents(ctx, outputPath+".out.json", WithContentFetchCommand("type"))
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.out.json", outputPath)
	}
	resultPkg.XMLOutput, err = c.GetFileContents(ctx, outputPath+".xml", WithContentFetchCommand("type"))
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.xml", outputPath)
	}
	return resultPkg, nil
}

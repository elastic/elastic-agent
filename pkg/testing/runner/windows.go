// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// WindowsRunner is a handler for running tests on Windows
type WindowsRunner struct{}

// Prepare the test
func (WindowsRunner) Prepare(ctx context.Context, sshClient SSHClient, logger Logger, arch string, goVersion string) error {
	// install chocolatey
	logger.Logf("Installing chocolatey")
	chocoInstall := `"[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"`
	stdOut, errOut, err := sshRunPowershell(ctx, sshClient, chocoInstall)
	if err != nil {
		return fmt.Errorf("failed to install chocolatey: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// reconnect to get updated environment variables (1 minute as it should be quick to reconnect)
	err = sshClient.ReconnectWithTimeout(ctx, 1*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to reconnect: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// install curl
	logger.Logf("Installing curl")
	stdOut, errOut, err = sshClient.Exec(ctx, "choco", []string{"install", "-y", "curl"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install curl: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// install make
	logger.Logf("Installing make")
	stdOut, errOut, err = sshClient.Exec(ctx, "choco", []string{"install", "-y", "make"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install make: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// install golang (doesn't use choco, because sometimes it doesn't have the required version)
	logger.Logf("Installing golang %s (%s)", goVersion, arch)
	downloadURL := fmt.Sprintf("https://go.dev/dl/go%s.windows-%s.msi", goVersion, arch)
	filename := path.Base(downloadURL)
	stdOut, errOut, err = sshClient.Exec(ctx, "curl", []string{"-Ls", downloadURL, "--output", filename}, nil)
	if err != nil {
		return fmt.Errorf("failed to download go from %s with curl: %w (stdout: %s, stderr: %s)", downloadURL, err, stdOut, errOut)
	}
	stdOut, errOut, err = sshClient.Exec(ctx, "msiexec", []string{"/i", filename, "/qn"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install go: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// reconnect to get updated environment variables (1 minute as it should be quick to reconnect)
	err = sshClient.ReconnectWithTimeout(ctx, 1*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to reconnect: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	return nil
}

// Copy places the required files on the host.
func (WindowsRunner) Copy(ctx context.Context, sshClient SSHClient, logger Logger, repoArchive string, build Build) error {
	// copy the archive and extract it on the host (tar exists and can extract zip on windows)
	logger.Logf("Copying repo")
	destRepoName := filepath.Base(repoArchive)
	err := sshClient.Copy(repoArchive, destRepoName)
	if err != nil {
		return fmt.Errorf("failed to SCP repo archive %s: %w", repoArchive, err)
	}

	// ensure that agent directory is removed (possible it already exists if instance already used)
	// Windows errors if the directory doesn't exist, it's okay if it doesn't ignore any error here
	_, _, _ = sshClient.Exec(ctx, "rmdir", []string{"agent", "/s", "/q"}, nil)

	stdOut, errOut, err := sshClient.Exec(ctx, "mkdir", []string{"agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to mkdir agent: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshClient.Exec(ctx, "tar", []string{"-xf", destRepoName, "-C", "agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to unzip %s to agent directory: %w (stdout: %s, stderr: %s)", destRepoName, err, stdOut, errOut)
	}

	// install mage and prepare for testing
	logger.Logf("Running make mage and prepareOnRemote")
	stdOut, errOut, err = sshClient.Exec(ctx, "cd", []string{"agent", "&&", "make", "mage", "&&", "mage", "integration:prepareOnRemote"}, nil)
	if err != nil {
		return fmt.Errorf("failed to to perform make mage and prepareOnRemote: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// determine if the build needs to be replaced on the host
	// if it already exists and the SHA512 are the same contents, then
	// there is no reason to waste time uploading the build
	copyBuild := true
	localSHA512, err := os.ReadFile(build.SHA512Path)
	if err != nil {
		return fmt.Errorf("failed to read local SHA52 contents %s: %w", build.SHA512Path, err)
	}
	hostSHA512Path := filepath.Base(build.SHA512Path)
	hostSHA512, err := sshClient.GetFileContents(ctx, hostSHA512Path, WithContentFetchCommand("type"))
	if err == nil {
		if string(localSHA512) == string(hostSHA512) {
			logger.Logf("Skipping copy agent build %s; already the same", filepath.Base(build.Path))
			copyBuild = false
		}
	}

	if copyBuild {
		// ensure the existing copies are removed first
		toRemove := filepath.Base(build.Path)
		stdOut, errOut, err = sshClient.Exec(ctx,
			"del", []string{toRemove, "/f", "/q"}, nil)
		if err != nil {
			return fmt.Errorf("failed to remove %q: %w (stdout: %q, stderr: %q)",
				toRemove, err, stdOut, errOut)
		}

		toRemove = filepath.Base(build.SHA512Path)
		stdOut, errOut, err = sshClient.Exec(ctx,
			"del", []string{toRemove, "/f", "/q"}, nil)
		if err != nil {
			return fmt.Errorf("failed to remove %q: %w (stdout: %q, stderr: %q)",
				toRemove, err, stdOut, errOut)
		}

		logger.Logf("Copying agent build %s", filepath.Base(build.Path))
	}

	for _, buildPath := range []string{build.Path, build.SHA512Path} {
		if copyBuild {
			err = sshClient.Copy(buildPath, filepath.Base(buildPath))
			if err != nil {
				return fmt.Errorf("failed to SCP build %s: %w", filepath.Base(buildPath), err)
			}
		}
		insideAgentDir := filepath.Join("agent", buildPath)
		// possible the build path already exists, 'mkdir' on windows will fail if it already exists
		// error from this call is ignored because of it
		_, _, _ = sshClient.Exec(ctx, "mkdir", []string{toWindowsPath(filepath.Dir(insideAgentDir))}, nil)
		stdOut, errOut, err = sshClient.Exec(ctx, "mklink", []string{"/h", toWindowsPath(insideAgentDir), filepath.Base(buildPath)}, nil)
		if err != nil {
			return fmt.Errorf("failed to hard link %s to %s: %w (stdout: %s, stderr: %s)", filepath.Base(buildPath), toWindowsPath(insideAgentDir), err, stdOut, errOut)
		}
	}

	return nil
}

// Run the test
func (WindowsRunner) Run(ctx context.Context, verbose bool, c SSHClient, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error) {
	var tests []string
	for _, pkg := range batch.Tests {
		for _, test := range pkg.Tests {
			tests = append(tests, fmt.Sprintf("%s:%s", pkg.Name, test.Name))
		}
	}
	var sudoTests []string
	for _, pkg := range batch.SudoTests {
		for _, test := range pkg.Tests {
			sudoTests = append(sudoTests, fmt.Sprintf("%s:%s", pkg.Name, test.Name))
		}
	}

	var result OSRunnerResult
	if len(tests) > 0 {
		script := toPowershellScript(agentVersion, prefix, verbose, tests, env)

		results, err := runTestsOnWindows(ctx, logger, "non-sudo", prefix, script, c, batch.SudoTests)
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("error running non-sudo tests: %w", err)
		}
		result.Packages = results
	}

	if len(sudoTests) > 0 {
		prefix := fmt.Sprintf("%s-sudo", prefix)
		script := toPowershellScript(agentVersion, prefix, verbose, sudoTests, env)

		results, err := runTestsOnWindows(ctx, logger, "sudo", prefix, script, c, batch.SudoTests)
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("error running sudo tests: %w", err)
		}
		result.SudoPackages = results

	}
	return result, nil
}

// Diagnostics gathers any diagnostics from the host.
func (WindowsRunner) Diagnostics(ctx context.Context, sshClient SSHClient, logger Logger, destination string) error {
	diagnosticDir := "agent\\build\\diagnostics"
	stdOut, _, err := sshClient.Exec(ctx, "dir", []string{diagnosticDir, "/b"}, nil)
	if err != nil {
		//nolint:nilerr // failed to list the directory, probably don't have any diagnostics (do nothing)
		return nil
	}
	eachDiagnostic := strings.Split(string(stdOut), "\n")
	for _, filename := range eachDiagnostic {
		filename = strings.TrimSpace(filename)
		if filename == "" {
			continue
		}

		// don't use filepath.Join as we need this to work in Linux/Darwin as well
		// this is because if we use `filepath.Join` on a Linux/Darwin host connected to a Windows host
		// it will use a `/` and that will be incorrect for Windows
		fp := fmt.Sprintf("%s\\%s", diagnosticDir, filename)
		// use filepath.Join on this path because it's a path on this specific host platform
		dp := filepath.Join(destination, filename)
		logger.Logf("Copying diagnostic %s", filename)
		out, err := os.Create(dp)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", dp, err)
		}
		err = sshClient.GetFileContentsOutput(ctx, fp, out, WithContentFetchCommand("type"))
		_ = out.Close()
		if err != nil {
			return fmt.Errorf("failed to copy file from remote host to %s: %w", dp, err)
		}
	}
	return nil
}

func sshRunPowershell(ctx context.Context, sshClient SSHClient, cmd string) ([]byte, []byte, error) {
	return sshClient.Exec(ctx, "powershell", []string{
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

func runTestsOnWindows(ctx context.Context, logger Logger, name string, prefix string, script string, sshClient SSHClient, tests []define.BatchPackageTests) ([]OSRunnerPackageResult, error) {
	execTest := strings.NewReader(script)

	session, err := sshClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to start session: %w", err)
	}

	session.Stdout = newPrefixOutput(logger, fmt.Sprintf("Test output (%s) (stdout): ", name))
	session.Stderr = newPrefixOutput(logger, fmt.Sprintf("Test output (%s) (stderr): ", name))
	session.Stdin = execTest
	// allowed to fail because tests might fail
	logger.Logf("Running %s tests...", name)
	err = session.Run("powershell -noprofile -noninteractive -")
	if err != nil {
		logger.Logf("%s tests failed: %s", name, err)
	}
	// this seems to always return an error
	_ = session.Close()

	var result []OSRunnerPackageResult
	// fetch the contents for each package
	for _, pkg := range tests {
		resultPkg, err := getWindowsRunnerPackageResult(ctx, sshClient, pkg, prefix)
		if err != nil {
			return nil, err
		}
		result = append(result, resultPkg)
	}
	return result, nil
}

func toWindowsPath(path string) string {
	return strings.ReplaceAll(path, "/", "\\")
}

func getWindowsRunnerPackageResult(ctx context.Context, sshClient SSHClient, pkg define.BatchPackageTests, prefix string) (OSRunnerPackageResult, error) {
	var err error
	var resultPkg OSRunnerPackageResult
	resultPkg.Name = pkg.Name
	outputPath := fmt.Sprintf("%%home%%\\agent\\build\\TEST-go-remote-%s.%s", prefix, filepath.Base(pkg.Name))
	resultPkg.Output, err = sshClient.GetFileContents(ctx, outputPath+".out", WithContentFetchCommand("type"))
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.out", outputPath)
	}
	resultPkg.JSONOutput, err = sshClient.GetFileContents(ctx, outputPath+".out.json", WithContentFetchCommand("type"))
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.out.json", outputPath)
	}
	resultPkg.XMLOutput, err = sshClient.GetFileContents(ctx, outputPath+".xml", WithContentFetchCommand("type"))
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.xml", outputPath)
	}
	return resultPkg, nil
}

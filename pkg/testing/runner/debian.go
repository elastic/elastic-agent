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

	"golang.org/x/crypto/ssh"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// DebianRunner is a handler for running tests on Linux
type DebianRunner struct{}

// Prepare the test
func (DebianRunner) Prepare(ctx context.Context, sshClient *ssh.Client, logger Logger, arch string, goVersion string) error {
	// prepare build-essential and unzip
	//
	// apt-get update and install are so terrible that we have to place this in a loop, because in some cases the
	// apt-get update says it works, but it actually fails. so we add 3 tries here
	var err error
	for i := 0; i < 3; i++ {
		err = func() error {
			updateCtx, updateCancel := context.WithTimeout(ctx, 3*time.Minute)
			defer updateCancel()
			logger.Logf("Running apt-get update")
			// `-o APT::Update::Error-Mode=any` ensures that any warning is tried as an error, so the retry
			// will occur (without this we get random failures)
			stdOut, errOut, err := sshRunCommandWithRetry(updateCtx, sshClient, "sudo", []string{"apt-get", "update", "-o APT::Update::Error-Mode=any"}, 15*time.Second)
			if err != nil {
				return fmt.Errorf("failed to run apt-get update: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
			}
			return func() error {
				// golang is installed below and not using the package manager, ensures that the exact version
				// of golang is used for the running of the test
				installCtx, installCancel := context.WithTimeout(ctx, 1*time.Minute)
				defer installCancel()
				logger.Logf("Install build-essential and unzip")
				stdOut, errOut, err = sshRunCommandWithRetry(installCtx, sshClient, "sudo", []string{"apt-get", "install", "-y", "build-essential", "unzip"}, 5*time.Second)
				if err != nil {
					return fmt.Errorf("failed to install build-essential and unzip: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
				}
				return nil
			}()
		}()
		if err == nil {
			// installation was successful
			break
		}
		logger.Logf("Failed to install build-essential and unzip; will wait 15 seconds and try again")
		<-time.After(15 * time.Second)
	}
	if err != nil {
		// seems after 3 tries it still failed
		return err
	}

	// prepare golang
	logger.Logf("Install golang %s (%s)", goVersion, arch)
	downloadURL := fmt.Sprintf("https://go.dev/dl/go%s.linux-%s.tar.gz", goVersion, arch)
	filename := path.Base(downloadURL)
	stdOut, errOut, err := sshRunCommand(ctx, sshClient, "curl", []string{"-Ls", downloadURL, "--output", filename}, nil)
	if err != nil {
		return fmt.Errorf("failed to download go from %s with curl: %w (stdout: %s, stderr: %s)", downloadURL, err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, sshClient, "sudo", []string{"tar", "-C", "/usr/local", "-xzf", filename}, nil)
	if err != nil {
		return fmt.Errorf("failed to extract go to /usr/local with tar: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, sshClient, "sudo", []string{"ln", "-s", "/usr/local/go/bin/go", "/usr/bin/go"}, nil)
	if err != nil {
		return fmt.Errorf("failed to symlink /usr/local/go/bin/go to /usr/bin/go: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, sshClient, "sudo", []string{"ln", "-s", "/usr/local/go/bin/gofmt", "/usr/bin/gofmt"}, nil)
	if err != nil {
		return fmt.Errorf("failed to symlink /usr/local/go/bin/gofmt to /usr/bin/gofmt: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	return nil
}

// Copy places the required files on the host.
func (DebianRunner) Copy(ctx context.Context, sshClient *ssh.Client, logger Logger, repoArchive string, build Build) error {
	// copy the archive and extract it on the host
	logger.Logf("Copying repo")
	destRepoName := filepath.Base(repoArchive)
	err := sshSCP(sshClient, repoArchive, destRepoName)
	if err != nil {
		return fmt.Errorf("failed to SCP repo archive %s: %w", repoArchive, err)
	}

	// ensure that agent directory is removed (possible it already exists if instance already used)
	stdout, stderr, err := sshRunCommand(ctx,
		sshClient, "sudo", []string{"rm", "-rf", "agent"}, nil)
	if err != nil {
		return fmt.Errorf(
			"failed to remove agent directory before unziping new one: %w. stdout: %q, stderr: %q",
			err, stdout, stderr)
	}

	stdOut, errOut, err := sshRunCommand(ctx, sshClient, "unzip", []string{destRepoName, "-d", "agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to unzip %s to agent directory: %w (stdout: %s, stderr: %s)", destRepoName, err, stdOut, errOut)
	}

	// prepare for testing
	logger.Logf("Running make mage and prepareOnRemote")
	envs := `GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH"`
	installMage := strings.NewReader(fmt.Sprintf(`cd agent && %s make mage && %s mage integration:prepareOnRemote`, envs, envs))
	stdOut, errOut, err = sshRunCommand(ctx, sshClient, "bash", nil, installMage)
	if err != nil {
		return fmt.Errorf("failed to perform make mage and prepareOnRemote: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
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
	hostSHA512, err := sshGetFileContents(ctx, sshClient, hostSHA512Path)
	if err == nil {
		if string(localSHA512) == string(hostSHA512) {
			logger.Logf("Skipping copy agent build %s; already the same", filepath.Base(build.Path))
			copyBuild = false
		}
	}

	if copyBuild {
		// ensure the existing copies are removed first
		toRemove := filepath.Base(build.Path)
		stdOut, errOut, err = sshRunCommand(ctx,
			sshClient, "sudo", []string{"rm", "-f", toRemove}, nil)
		if err != nil {
			return fmt.Errorf("failed to remove %q: %w (stdout: %q, stderr: %q)",
				toRemove, err, stdOut, errOut)
		}

		toRemove = filepath.Base(build.SHA512Path)
		stdOut, errOut, err = sshRunCommand(ctx,
			sshClient, "sudo", []string{"rm", "-f", toRemove}, nil)
		if err != nil {
			return fmt.Errorf("failed to remove %q: %w (stdout: %q, stderr: %q)",
				toRemove, err, stdOut, errOut)
		}

		logger.Logf("Copying agent build %s", filepath.Base(build.Path))
	}

	for _, buildPath := range []string{build.Path, build.SHA512Path} {
		if copyBuild {
			err = sshSCP(sshClient, buildPath, filepath.Base(buildPath))
			if err != nil {
				return fmt.Errorf("failed to SCP build %s: %w", filepath.Base(buildPath), err)
			}
		}
		insideAgentDir := filepath.Join("agent", buildPath)
		stdOut, errOut, err = sshRunCommand(ctx, sshClient, "mkdir", []string{"-p", filepath.Dir(insideAgentDir)}, nil)
		if err != nil {
			return fmt.Errorf("failed to create %s directory: %w (stdout: %s, stderr: %s)", filepath.Dir(insideAgentDir), err, stdOut, errOut)
		}
		stdOut, errOut, err = sshRunCommand(ctx, sshClient, "ln", []string{filepath.Base(buildPath), insideAgentDir}, nil)
		if err != nil {
			return fmt.Errorf("failed to hard link %s to %s: %w (stdout: %s, stderr: %s)", filepath.Base(buildPath), insideAgentDir, err, stdOut, errOut)
		}
	}

	return nil
}

// Run the test
func (DebianRunner) Run(ctx context.Context, verbose bool, sshClient *ssh.Client, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error) {
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

	logArg := ""
	if verbose {
		logArg = "-v"
	}
	var result OSRunnerResult
	if len(tests) > 0 {
		vars := fmt.Sprintf(`GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH" AGENT_VERSION="%s" TEST_DEFINE_PREFIX="%s" TEST_DEFINE_TESTS="%s"`, agentVersion, prefix, strings.Join(tests, ","))
		vars = extendVars(vars, env)

		script := fmt.Sprintf(`cd agent && %s ~/go/bin/mage %s integration:testOnRemote`, vars, logArg)
		results, err := runTests(ctx, logger, "non-sudo", prefix, script, sshClient, batch.Tests)
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("error running non-sudo tests: %w", err)
		}
		result.Packages = results
	}

	if len(sudoTests) > 0 {
		prefix := fmt.Sprintf("%s-sudo", prefix)
		vars := fmt.Sprintf(`GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH" AGENT_VERSION="%s" TEST_DEFINE_PREFIX="%s" TEST_DEFINE_TESTS="%s"`, agentVersion, prefix, strings.Join(sudoTests, ","))
		vars = extendVars(vars, env)
		script := fmt.Sprintf(`cd agent && sudo %s ~/go/bin/mage %s integration:testOnRemote`, vars, logArg)

		results, err := runTests(ctx, logger, "sudo", prefix, script, sshClient, batch.SudoTests)
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("error running sudo tests: %w", err)
		}
		result.SudoPackages = results
	}

	return result, nil
}

// Diagnostics gathers any diagnostics from the host.
func (DebianRunner) Diagnostics(ctx context.Context, c *ssh.Client, logger Logger, destination string) error {
	// take ownership, as sudo tests will create with root permissions (allow to fail in the case it doesn't exist)
	diagnosticDir := "$HOME/agent/build/diagnostics"
	_, _, _ = sshRunCommand(ctx, c, "sudo", []string{"chown", "-R", "$USER:$USER", diagnosticDir}, nil)
	stdOut, _, err := sshRunCommand(ctx, c, "ls", []string{"-1", diagnosticDir}, nil)
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

		// don't use filepath.Join as we need this to work in Windows as well
		// this is because if we use `filepath.Join` on a Windows host connected to a Linux host
		// it will use a `\` and that will be incorrect for Linux
		fp := fmt.Sprintf("%s/%s", diagnosticDir, filename)
		// use filepath.Join on this path because it's a path on this specific host platform
		dp := filepath.Join(destination, filename)
		logger.Logf("Copying diagnostic %s", filename)
		out, err := os.Create(dp)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", dp, err)
		}
		err = sshGetFileContentsOutput(ctx, c, fp, out)
		_ = out.Close()
		if err != nil {
			return fmt.Errorf("failed to copy file from remote host to %s: %w", dp, err)
		}
	}
	return nil
}

func runTests(ctx context.Context, logger Logger, name string, prefix string, script string, sshClient *ssh.Client, tests []define.BatchPackageTests) ([]OSRunnerPackageResult, error) {
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
	err = session.Run("bash")
	if err != nil {
		logger.Logf("%s tests failed: %s", name, err)
	}
	// this seems to always return an error
	_ = session.Close()

	var result []OSRunnerPackageResult
	// fetch the contents for each package
	for _, pkg := range tests {
		resultPkg, err := getRunnerPackageResult(ctx, sshClient, pkg, prefix)
		if err != nil {
			return nil, err
		}
		result = append(result, resultPkg)
	}
	return result, nil
}

func getRunnerPackageResult(ctx context.Context, c *ssh.Client, pkg define.BatchPackageTests, prefix string) (OSRunnerPackageResult, error) {
	var err error
	var resultPkg OSRunnerPackageResult
	resultPkg.Name = pkg.Name
	outputPath := fmt.Sprintf("$HOME/agent/build/TEST-go-remote-%s.%s", prefix, filepath.Base(pkg.Name))
	resultPkg.Output, err = sshGetFileContents(ctx, c, outputPath+".out")
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.out", outputPath)
	}
	resultPkg.JSONOutput, err = sshGetFileContents(ctx, c, outputPath+".out.json")
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.out.json", outputPath)
	}
	resultPkg.XMLOutput, err = sshGetFileContents(ctx, c, outputPath+".xml")
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.xml", outputPath)
	}
	return resultPkg, nil
}

func extendVars(vars string, env map[string]string) string {
	var envStr []string
	for k, v := range env {
		envStr = append(envStr, fmt.Sprintf(`%s="%s"`, k, v))
	}
	return fmt.Sprintf("%s %s", vars, strings.Join(envStr, " "))
}

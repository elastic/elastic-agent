package runner

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const setupPath = `
echo 'PATH=~/go/bin:$PATH' >> ~/.bashrc
`

type DebianRunner struct{}

func (DebianRunner) Prepare(ctx context.Context, c *ssh.Client, instanceName string, arch string, goVersion string, repoArchive string, buildPath string) error {
	// prepare build-essential and unzip
	//
	// apt-get update and install are so terrible that we have to place this in a loop, because in some cases the
	// apt-get update says it works, but it actually fails. so we add 3 tries here
	var err error
	for i := 0; i < 3; i++ {
		err = func() error {
			updateCtx, updateCancel := context.WithTimeout(ctx, 3*time.Minute)
			defer updateCancel()
			fmt.Printf(">>> Running apt-get update on %s\n", instanceName)
			// `-o APT::Update::Error-Mode=any` ensures that any warning is tried as an error, so the retry
			// will occur (without this we get random failures)
			stdOut, errOut, err := sshRunCommandWithRetry(updateCtx, c, "sudo", []string{"apt-get", "update", "-o APT::Update::Error-Mode=any"}, 15*time.Second)
			if err != nil {
				return fmt.Errorf("failed to run apt-get update: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
			}
			return func() error {
				// golang is installed below and not using the package manager, ensures that the exact version
				// of golang is used for the running of the test
				installCtx, installCancel := context.WithTimeout(ctx, 1*time.Minute)
				defer installCancel()
				fmt.Printf(">>> Install build-essential and unzip on %s\n", instanceName)
				stdOut, errOut, err = sshRunCommandWithRetry(installCtx, c, "sudo", []string{"apt-get", "install", "-y", "build-essential", "unzip"}, 5*time.Second)
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
		fmt.Printf(">>> Failed to install build-essential and unzip on %s; will wait 15 seconds and try again\n", instanceName)
		<-time.After(15 * time.Second)
	}
	if err != nil {
		// seems after 3 tries it still failed
		return err
	}

	// prepare golang
	fmt.Printf(">>> Install golang %s (%s) on %s\n", goVersion, arch, instanceName)
	downloadURL := fmt.Sprintf("https://go.dev/dl/go%s.linux-%s.tar.gz", goVersion, arch)
	filename := path.Base(downloadURL)
	stdOut, errOut, err := sshRunCommand(ctx, c, "curl", []string{"-Ls", downloadURL, "--output", filename}, nil)
	if err != nil {
		return fmt.Errorf("failed to download go from %s with curl: %w (stdout: %s, stderr: %s)", downloadURL, err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "sudo", []string{"tar", "-C", "/usr/local", "-xzf", filename}, nil)
	if err != nil {
		return fmt.Errorf("failed to extract go to /usr/local with tar: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "sudo", []string{"ln", "-s", "/usr/local/go/bin/go", "/usr/bin/go"}, nil)
	if err != nil {
		return fmt.Errorf("failed to symlink /usr/local/go/bin/go to /usr/bin/go: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "sudo", []string{"ln", "-s", "/usr/local/go/bin/gofmt", "/usr/bin/gofmt"}, nil)
	if err != nil {
		return fmt.Errorf("failed to symlink /usr/local/go/bin/gofmt to /usr/bin/gofmt: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// copy the archive and extract it on the host
	fmt.Printf(">>> Copying repo to %s\n", instanceName)
	destRepoName := filepath.Base(repoArchive)
	err = sshSCP(c, repoArchive, destRepoName)
	if err != nil {
		return fmt.Errorf("failed to SCP repo archive %s: %w", repoArchive, err)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "unzip", []string{destRepoName, "-d", "agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to unzip %s to agent directory: %w (stdout: %s, stderr: %s)", destRepoName, err, stdOut, errOut)
	}

	// install mage and prepare for testing
	fmt.Printf(">>> Running make mage and prepareOnRemote on %s\n", instanceName)
	envs := `GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH"`
	installMage := strings.NewReader(fmt.Sprintf(`cd agent && %s make mage && %s mage integration:prepareOnRemote`, envs, envs))
	stdOut, errOut, err = sshRunCommand(ctx, c, "bash", nil, installMage)
	if err != nil {
		return fmt.Errorf("failed to to perform make mage and prepareOnRemote: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// place the build for the agent on the host
	fmt.Printf(">>> Copying agent build %s to %s\n", filepath.Base(buildPath), instanceName)
	err = sshSCP(c, buildPath, filepath.Base(buildPath))
	if err != nil {
		return fmt.Errorf("failed to SCP build %s: %w", filepath.Base(buildPath), err)
	}
	insideAgentDir := filepath.Join("agent", buildPath)
	stdOut, errOut, err = sshRunCommand(ctx, c, "mkdir", []string{"-p", filepath.Dir(insideAgentDir)}, nil)
	if err != nil {
		return fmt.Errorf("failed to create %s directory: %w (stdout: %s, stderr: %s)", filepath.Dir(insideAgentDir), err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "mv", []string{filepath.Base(buildPath), insideAgentDir}, nil)
	if err != nil {
		return fmt.Errorf("failed to move %s to %s: %w (stdout: %s, stderr: %s)", filepath.Base(buildPath), insideAgentDir, err, stdOut, errOut)
	}

	return nil
}

func (DebianRunner) Run(ctx context.Context, c *ssh.Client, instanceName string, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error) {
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
		vars := fmt.Sprintf(`GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH" AGENT_VERSION="%s" TEST_DEFINE_PREFIX="%s" TEST_DEFINE_TESTS="%s"`, agentVersion, prefix, strings.Join(tests, ","))
		vars = extendVars(vars, env)
		fmt.Printf(">>> Starting tests on %s\n", instanceName)
		script := fmt.Sprintf(`cd agent && %s ~/go/bin/mage integration:testOnRemote`, vars)
		execTest := strings.NewReader(script)

		session, err := c.NewSession()
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("failed to start session: %w", err)
		}

		session.Stdout = newPrefixOutput(os.Stdout, fmt.Sprintf(">>> Executing tests on %s (stdout): ", instanceName))
		session.Stderr = newPrefixOutput(os.Stderr, fmt.Sprintf(">>> Executing tests on %s (stderr): ", instanceName))
		session.Stdin = execTest
		// allowed to fail because tests might fail
		_ = session.Run("bash")
		_ = session.Close()

		// fetch the contents for each package
		for _, pkg := range batch.Tests {
			resultPkg, err := getRunnerPackageResult(ctx, c, pkg, prefix)
			if err != nil {
				return OSRunnerResult{}, err
			}
			result.Packages = append(result.Packages, resultPkg)
		}
	}

	if len(sudoTests) > 0 {
		prefix := fmt.Sprintf("%s-sudo", prefix)
		vars := fmt.Sprintf(`GOPATH="$HOME/go" PATH="$HOME/go/bin:$PATH" AGENT_VERSION="%s" TEST_DEFINE_PREFIX="%s" TEST_DEFINE_TESTS="%s"`, agentVersion, prefix, strings.Join(sudoTests, ","))
		vars = extendVars(vars, env)
		fmt.Printf(">>> Starting sudo tests on %s\n", instanceName)
		script := fmt.Sprintf(`cd agent && sudo %s ~/go/bin/mage integration:testOnRemote`, vars)
		execTest := strings.NewReader(script)

		session, err := c.NewSession()
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("failed to start session: %w", err)
		}

		session.Stdout = newPrefixOutput(os.Stdout, fmt.Sprintf(">>> Executing sudo tests on %s (stdout): ", instanceName))
		session.Stderr = newPrefixOutput(os.Stderr, fmt.Sprintf(">>> Executing sudo tests on %s (stderr): ", instanceName))
		session.Stdin = execTest
		// allowed to fail because tests might fail
		_ = session.Run("bash")
		_ = session.Close()

		// fetch the contents for each package
		for _, pkg := range batch.SudoTests {
			resultPkg, err := getRunnerPackageResult(ctx, c, pkg, prefix)
			if err != nil {
				return OSRunnerResult{}, err
			}
			result.SudoPackages = append(result.SudoPackages, resultPkg)
		}
	}
	return result, nil
}

func getRunnerPackageResult(ctx context.Context, c *ssh.Client, pkg define.BatchPackageTests, prefix string) (OSRunnerPackageResult, error) {
	var err error
	var resultPkg OSRunnerPackageResult
	resultPkg.Name = pkg.Name
	outputPath := fmt.Sprintf("$HOME/agent/build/TEST-go-remote-%s.%s.out", prefix, filepath.Base(pkg.Name))
	resultPkg.Output, err = sshGetFileContents(ctx, c, outputPath)
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s", outputPath)
	}
	resultPkg.JSONOutput, err = sshGetFileContents(ctx, c, outputPath+".json")
	if err != nil {
		return OSRunnerPackageResult{}, fmt.Errorf("failed to fetched test output at %s.json", outputPath)
	}
	resultPkg.XMLOutput, err = sshGetFileContents(ctx, c, outputPath+".json")
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

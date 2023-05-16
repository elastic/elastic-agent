package runner

import (
	"context"
	"fmt"
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

func (DebianRunner) Prepare(ctx context.Context, c *ssh.Client, instanceID string, arch string, goVersion string, repoArchive string, buildPath string) error {
	// prepare make and unzip
	updateCtx, updateCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer updateCancel()
	fmt.Printf(">>> Running apt-get update on %s\n", instanceID)
	stdOut, errOut, err := sshRunCommandWithRetry(updateCtx, c, "sudo", []string{"apt-get", "update"}, 15*time.Second)
	if err != nil {
		return fmt.Errorf("failed to run apt-get update: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	// golang is installed below and not using the package manager, ensures that the exact version
	// of golang is used for the running of the test
	installCtx, installCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer installCancel()
	fmt.Printf(">>> Install make and unzip on %s\n", instanceID)
	stdOut, errOut, err = sshRunCommandWithRetry(installCtx, c, "sudo", []string{"apt-get", "install", "-y", "make", "unzip"}, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to install make and unzip: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	// prepare golang
	fmt.Printf(">>> Install golang %s (%s) on %s\n", goVersion, arch, instanceID)
	downloadURL := fmt.Sprintf("https://go.dev/dl/go%s.linux-%s.tar.gz", goVersion, arch)
	filename := path.Base(downloadURL)
	stdOut, errOut, err = sshRunCommand(ctx, c, "curl", []string{"-Ls", downloadURL, "--output", filename}, nil)
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
	fmt.Printf(">>> Copying repo to %s\n", instanceID)
	err = sshSCP(c, repoArchive)
	if err != nil {
		return fmt.Errorf("failed to SCP repo archive %s: %w", repoArchive, err)
	}
	destRepoName := filepath.Base(repoArchive)
	stdOut, errOut, err = sshRunCommand(ctx, c, "unzip", []string{destRepoName, "-d", "agent"}, nil)
	if err != nil {
		return fmt.Errorf("failed to unzip %s to agent directory: %w (stdout: %s, stderr: %s)", destRepoName, err, stdOut, errOut)
	}

	// place the build for the agent on the host
	fmt.Printf(">>> Copying agent build %s to %s\n", filepath.Base(buildPath), instanceID)
	stdOut, errOut, err = sshRunCommand(ctx, c, "mkdir", []string{"-p", filepath.Dir(buildPath)}, nil)
	if err != nil {
		return fmt.Errorf("failed to create %s directory: %w (stdout: %s, stderr: %s)", filepath.Dir(buildPath), err, stdOut, errOut)
	}
	err = sshSCP(c, buildPath)
	if err != nil {
		return fmt.Errorf("failed to SCP build %s: %w", filepath.Base(buildPath), err)
	}

	// install mage using the Makefile
	fmt.Printf(">>> Running make mage on %s\n", instanceID)
	addPath := strings.NewReader(`echo 'PATH=~/go/bin:$PATH' >> ~/.bashrc`)
	stdOut, errOut, err = sshRunCommand(ctx, c, "bash", nil, addPath)
	if err != nil {
		return fmt.Errorf("failed to install mage through Makefile: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}
	stdOut, errOut, err = sshRunCommand(ctx, c, "make", []string{"-C", "agent", "mage"}, nil)
	if err != nil {
		return fmt.Errorf("failed to install mage through Makefile: %w (stdout: %s, stderr: %s)", err, stdOut, errOut)
	}

	return nil
}

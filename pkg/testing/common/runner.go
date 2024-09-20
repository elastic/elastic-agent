package common

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ssh"
)

// OSRunnerPackageResult is the result for each package.
type OSRunnerPackageResult struct {
	// Name is the package name.
	Name string
	// Output is the raw test output.
	Output []byte
	// XMLOutput is the XML Junit output.
	XMLOutput []byte
	// JSONOutput is the JSON output.
	JSONOutput []byte
}

// OSRunnerResult is the result of the test run provided by a OSRunner.
type OSRunnerResult struct {
	// Packages is the results for each package.
	Packages []OSRunnerPackageResult

	// SudoPackages is the results for each package that need to run as sudo.
	SudoPackages []OSRunnerPackageResult
}

// OSRunner provides an interface to run the tests on the OS.
type OSRunner interface {
	// Prepare prepares the runner to actual run on the host.
	Prepare(ctx context.Context, sshClient ssh.SSHClient, logger Logger, arch string, goVersion string) error
	// Copy places the required files on the host.
	Copy(ctx context.Context, sshClient ssh.SSHClient, logger Logger, repoArchive string, builds []Build) error
	// Run runs the actual tests and provides the result.
	Run(ctx context.Context, verbose bool, sshClient ssh.SSHClient, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error)
	// Diagnostics gathers any diagnostics from the host.
	Diagnostics(ctx context.Context, sshClient ssh.SSHClient, logger Logger, destination string) error
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/ssh"
	"os"
	"path/filepath"
	"strings"
	"time"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// KubernetesRunner is a handler for running tests against a Kubernetes cluster
type KubernetesRunner struct{}

// Prepare configures the host for running the test
func (KubernetesRunner) Prepare(ctx context.Context, sshClient ssh.SSHClient, logger common.Logger, arch string, goVersion string) error {
	return nil
}

// Copy places the required files on the host
func (KubernetesRunner) Copy(ctx context.Context, sshClient ssh.SSHClient, logger common.Logger, repoArchive string, builds []common.Build) error {
	return nil
}

// Run the test
func (KubernetesRunner) Run(ctx context.Context, verbose bool, sshClient ssh.SSHClient, logger common.Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (common.OSRunnerResult, error) {
	var goTestFlags []string
	rawTestFlags := os.Getenv("GOTEST_FLAGS")
	if rawTestFlags != "" {
		goTestFlags = strings.Split(rawTestFlags, " ")
	}

	maxDuration := 2 * time.Hour
	var result []common.OSRunnerPackageResult
	for _, pkg := range batch.Tests {
		packageTestsStrBuilder := strings.Builder{}
		packageTestsStrBuilder.WriteString("^(")
		for idx, test := range pkg.Tests {
			if idx > 0 {
				packageTestsStrBuilder.WriteString("|")
			}
			packageTestsStrBuilder.WriteString(test.Name)
		}
		packageTestsStrBuilder.WriteString(")$")

		testPrefix := fmt.Sprintf("%s.%s", prefix, filepath.Base(pkg.Name))
		testName := fmt.Sprintf("k8s-%s", testPrefix)
		fileName := fmt.Sprintf("build/TEST-go-%s", testName)
		extraFlags := make([]string, 0, len(goTestFlags)+6)
		if len(goTestFlags) > 0 {
			extraFlags = append(extraFlags, goTestFlags...)
		}
		extraFlags = append(extraFlags, "-test.shuffle", "on",
			"-test.timeout", maxDuration.String(), "-test.run", packageTestsStrBuilder.String())

		env["AGENT_VERSION"] = agentVersion
		env["TEST_DEFINE_PREFIX"] = testPrefix

		buildFolderAbsPath, err := filepath.Abs("build")
		if err != nil {
			return common.OSRunnerResult{}, err
		}

		podLogsPath := filepath.Join(buildFolderAbsPath, fmt.Sprintf("k8s-logs-%s", testPrefix))
		err = os.Mkdir(podLogsPath, 0755)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return common.OSRunnerResult{}, err
		}

		env["K8S_TESTS_POD_LOGS_BASE"] = podLogsPath

		params := devtools.GoTestArgs{
			LogName:         testName,
			OutputFile:      fileName + ".out",
			JUnitReportFile: fileName + ".xml",
			Packages:        []string{pkg.Name},
			Tags:            []string{"integration", "kubernetes"},
			ExtraFlags:      extraFlags,
			Env:             env,
		}
		err = devtools.GoTest(ctx, params)
		if err != nil {
			return common.OSRunnerResult{}, err
		}

		var resultPkg common.OSRunnerPackageResult
		resultPkg.Name = pkg.Name
		outputPath := fmt.Sprintf("build/TEST-go-k8s-%s.%s", prefix, filepath.Base(pkg.Name))
		resultPkg.Output, err = os.ReadFile(outputPath + ".out")
		if err != nil {
			return common.OSRunnerResult{}, fmt.Errorf("failed to fetched test output at %s.out", outputPath)
		}
		resultPkg.JSONOutput, err = os.ReadFile(outputPath + ".out.json")
		if err != nil {
			return common.OSRunnerResult{}, fmt.Errorf("failed to fetched test output at %s.out.json", outputPath)
		}
		resultPkg.XMLOutput, err = os.ReadFile(outputPath + ".xml")
		if err != nil {
			return common.OSRunnerResult{}, fmt.Errorf("failed to fetched test output at %s.xml", outputPath)
		}
		result = append(result, resultPkg)
	}

	return common.OSRunnerResult{
		Packages: result,
	}, nil
}

// Diagnostics gathers any diagnostics from the host.
func (KubernetesRunner) Diagnostics(ctx context.Context, sshClient ssh.SSHClient, logger common.Logger, destination string) error {
	// does nothing for kubernetes
	return nil
}

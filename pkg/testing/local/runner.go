// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/ssh"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// Runner runs tests directly on the host running mage, mirroring
// kubernetes.Runner's use of devtools.GoTest instead of an SSH transport.
type Runner struct{}

// Prepare does nothing, the host running mage already has everything it needs.
func (Runner) Prepare(ctx context.Context, sshClient ssh.SSHClient, logger common.Logger, arch string, goVersion string) error {
	return nil
}

// Copy does nothing, tests run directly out of the local repo.
func (Runner) Copy(ctx context.Context, sshClient ssh.SSHClient, logger common.Logger, repoArchive string, builds []common.Build) error {
	return nil
}

// Run the test
func (Runner) Run(ctx context.Context, verbose bool, sshClient ssh.SSHClient, logger common.Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (common.OSRunnerResult, error) {
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
		testName := fmt.Sprintf("local-%s", testPrefix)
		fileName := fmt.Sprintf("build/TEST-go-%s", testName)
		extraFlags := make([]string, 0, len(goTestFlags)+6)
		if len(goTestFlags) > 0 {
			extraFlags = append(extraFlags, goTestFlags...)
		}
		extraFlags = append(extraFlags, "-test.shuffle", "on",
			"-test.timeout", maxDuration.String(), "-test.run", packageTestsStrBuilder.String())

		env["AGENT_VERSION"] = agentVersion
		env["TEST_DEFINE_PREFIX"] = testPrefix
		if _, ok := env["TEST_AGENT_DEVELOP"]; !ok {
			env["TEST_AGENT_DEVELOP"] = "true"
		}

		params := devtools.GoTestArgs{
			LogName:         testName,
			OutputFile:      fileName + ".out",
			JUnitReportFile: fileName + ".xml",
			Packages:        []string{pkg.Name},
			Tags:            []string{"integration", "local"},
			ExtraFlags:      extraFlags,
			Env:             env,
		}
		err := devtools.GoTest(ctx, params)
		if err != nil {
			return common.OSRunnerResult{}, err
		}

		var resultPkg common.OSRunnerPackageResult
		resultPkg.Name = pkg.Name
		outputPath := fileName
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

// Diagnostics does nothing, diagnostics are already on the local host.
func (Runner) Diagnostics(ctx context.Context, sshClient ssh.SSHClient, logger common.Logger, destination string) error {
	return nil
}

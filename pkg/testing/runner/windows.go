// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"golang.org/x/crypto/ssh"
)

// WindowsRunner is a handler for running tests on Windows
type WindowsRunner struct{}

// Prepare the test
func (WindowsRunner) Prepare(ctx context.Context, c *ssh.Client, logger Logger, arch string, goVersion string, repoArchive string, buildPath string) error {
	return nil
}

// Run the test
func (WindowsRunner) Run(ctx context.Context, c *ssh.Client, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error) {
	return OSRunnerResult{}, fmt.Errorf("not done")
}

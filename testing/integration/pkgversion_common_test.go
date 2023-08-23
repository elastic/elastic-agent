// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
)

// getAgentVersion retrieves the agent version yaml output via CLI
func getAgentVersion(t *testing.T, f *integrationtest.Fixture, ctx context.Context, binaryOnly bool) []byte {
	args := []string{"version", "--yaml"}
	if binaryOnly {
		args = append(args, "--binary-only")
	}
	versionCmd, err := f.PrepareAgentCommand(ctx, args)
	require.NoError(t, err, "error preparing agent version command")

	actualVersionBytes, err := versionCmd.Output()
	require.NoError(t, err, "error executing 'version' command. Output %q", string(actualVersionBytes))
	return actualVersionBytes
}

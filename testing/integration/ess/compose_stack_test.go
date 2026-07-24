// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// composeStack manages a docker compose stack via the docker CLI.
type composeStack struct {
	file    string
	project string
}

// newDockerCompose writes content to a temp file and returns a composeStack
// that targets it. The temp file is removed when the test ends.
func newDockerCompose(t *testing.T, content string) *composeStack {
	t.Helper()
	f, err := os.CreateTemp("", "elastic-agent-compose-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })

	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Use a project name derived from the temp file so parallel tests don't
	// collide. Docker compose project names must be lowercase alphanumeric + dash.
	base := strings.TrimSuffix(strings.TrimPrefix(f.Name(), os.TempDir()), ".yml")
	base = strings.NewReplacer("/", "-", "_", "-").Replace(base)
	base = strings.Trim(base, "-")

	return &composeStack{file: f.Name(), project: base}
}

func (s *composeStack) up(ctx context.Context) error {
	return s.run(ctx, "up", "--detach", "--wait")
}

func (s *composeStack) down(ctx context.Context) error {
	return s.run(ctx, "down", "--remove-orphans", "--volumes", "--rmi", "local")
}

// serviceLogs returns an io.ReadCloser with the combined stdout/stderr logs of
// a single service, mirroring the testcontainers Container.Logs interface.
func (s *composeStack) serviceLogs(ctx context.Context, service string) (io.ReadCloser, error) {
	out, err := s.output(ctx, "logs", service)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(out)), nil
}

func (s *composeStack) run(ctx context.Context, args ...string) error {
	_, err := s.output(ctx, args...)
	return err
}

func (s *composeStack) output(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{"compose", "-f", s.file, "-p", s.project}
	cmd := exec.CommandContext(ctx, "docker", append(base, args...)...) //nolint:gosec // args are test-controlled docker compose subcommands
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker compose %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

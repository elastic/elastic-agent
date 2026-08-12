// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package docker

import (
	"context"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/common"
)

// skipIfDockerUnavailable skips the test if docker is not in PATH or the
// daemon is not reachable.
func skipIfDockerUnavailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "version").Run(); err != nil {
		t.Skipf("docker daemon not available: %s", err)
	}
}

// tLogger adapts *testing.T to common.Logger.
type tLogger struct{ t *testing.T }

func (l *tLogger) Logf(format string, args ...any) { l.t.Logf(format, args...) }

// startAlpine starts a detached alpine container that sleeps for 60 s and
// registers a cleanup to force-remove it when the test ends.
func startAlpine(t *testing.T, p *provisioner, name string) {
	t.Helper()
	_, err := p.docker(context.Background(), nil, "run", "-d", "--name", name, "alpine", "sleep", "60")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = p.docker(context.Background(), nil, "rm", "-fv", name)
	})
}

// containerExists returns true if `docker inspect <name>` succeeds.
func containerExists(p *provisioner, name string) bool {
	_, err := p.docker(context.Background(), nil, "inspect", name)
	return err == nil
}

func TestCheckDocker(t *testing.T) {
	skipIfDockerUnavailable(t)
	p := &provisioner{logger: &tLogger{t}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	assert.NoError(t, p.checkDocker(ctx))
}

func TestContainerIP(t *testing.T) {
	skipIfDockerUnavailable(t)
	p := &provisioner{logger: &tLogger{t}}
	name := containerName(t.Name())
	startAlpine(t, p, name)

	ip, err := p.containerIP(context.Background(), name)
	require.NoError(t, err)
	assert.NotEmpty(t, ip)
	assert.NotNil(t, net.ParseIP(ip), "expected a valid IP address, got %q", ip)
}

func TestClean(t *testing.T) {
	skipIfDockerUnavailable(t)

	t.Run("removes containers listed as instances", func(t *testing.T) {
		p := &provisioner{logger: &tLogger{t}}
		name := containerName(t.Name())
		startAlpine(t, p, name)

		require.True(t, containerExists(p, name), "container should exist before Clean")

		err := p.Clean(context.Background(), common.Config{}, []common.Instance{{Name: name}})
		require.NoError(t, err)

		assert.False(t, containerExists(p, name), "container should be removed after Clean")
	})

	t.Run("sweeps leftover containers by label", func(t *testing.T) {
		p := &provisioner{logger: &tLogger{t}}
		name := containerName(t.Name())

		// Create a container with the provisioner label but do NOT include it in the
		// instances list — simulating a container from a run cancelled mid-provision.
		_, err := p.docker(context.Background(), nil,
			"run", "-d",
			"--name", name,
			"--label", containerLabel,
			"alpine", "sleep", "60",
		)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = p.docker(context.Background(), nil, "rm", "-fv", name) })

		require.True(t, containerExists(p, name), "container should exist before Clean")

		// Clean with no instances: the label sweep must pick it up.
		err = p.Clean(context.Background(), common.Config{}, nil)
		require.NoError(t, err)

		assert.False(t, containerExists(p, name), "leftover container should be swept by Clean")
	})

	t.Run("sweeps leftover containers by name prefix", func(t *testing.T) {
		p := &provisioner{logger: &tLogger{t}}
		// Build a name that carries the provisioner prefix but no containerLabel,
		// to exercise the name-prefix branch of the sweep independently.
		name := containerName(t.Name())

		_, err := p.docker(context.Background(), nil,
			"run", "-d",
			"--name", name,
			"alpine", "sleep", "60",
		)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = p.docker(context.Background(), nil, "rm", "-fv", name) })

		require.True(t, containerExists(p, name), "container should exist before Clean")

		err = p.Clean(context.Background(), common.Config{}, nil)
		require.NoError(t, err)

		assert.False(t, containerExists(p, name), "prefix-matched leftover should be swept by Clean")
	})
}

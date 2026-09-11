// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package docker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/common"
)

// newTestProvisioner creates a provisioner with a live Docker client, skipping
// the test if Docker is unavailable.
func newTestProvisioner(t *testing.T) *provisioner {
	t.Helper()
	p := &provisioner{logger: &tLogger{t}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.checkDocker(ctx); err != nil {
		t.Skipf("docker not available: %s", err)
	}
	return p
}

// tLogger adapts *testing.T to common.Logger.
type tLogger struct{ t *testing.T }

func (l *tLogger) Logf(format string, args ...any) { l.t.Logf(format, args...) }

// pullImage pulls the named image, tolerating the case where it is already present.
func pullImage(t *testing.T, p *provisioner, image string) {
	t.Helper()
	ctx := context.Background()
	resp, err := p.client.ImagePull(ctx, image, dockerclient.ImagePullOptions{})
	require.NoError(t, err)
	require.NoError(t, resp.Wait(ctx))
}

// startAlpine starts a detached alpine container that sleeps for 60 s and
// registers a cleanup to force-remove it when the test ends.
func startAlpine(t *testing.T, p *provisioner, name string) {
	t.Helper()
	pullImage(t, p, "alpine")
	ctx := context.Background()
	resp, err := p.client.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
		Config:     &container.Config{Image: "alpine", Cmd: []string{"sleep", "60"}},
		HostConfig: &container.HostConfig{},
		Name:       name,
	})
	require.NoError(t, err)
	_, err = p.client.ContainerStart(ctx, resp.ID, dockerclient.ContainerStartOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = p.client.ContainerRemove(context.Background(), name,
			dockerclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	})
}

// containerExists returns true if ContainerInspect succeeds for the given name.
func containerExists(p *provisioner, name string) bool {
	_, err := p.client.ContainerInspect(context.Background(), name, dockerclient.ContainerInspectOptions{})
	return err == nil
}

// startAlpineLabeled starts a detached alpine container with the provisioner label.
func startAlpineLabeled(t *testing.T, p *provisioner, name string) {
	t.Helper()
	pullImage(t, p, "alpine")
	ctx := context.Background()
	resp, err := p.client.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
		Config: &container.Config{
			Image:  "alpine",
			Cmd:    []string{"sleep", "60"},
			Labels: map[string]string{containerLabel: ""},
		},
		HostConfig: &container.HostConfig{},
		Name:       name,
	})
	require.NoError(t, err)
	_, err = p.client.ContainerStart(ctx, resp.ID, dockerclient.ContainerStartOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = p.client.ContainerRemove(context.Background(), name,
			dockerclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	})
}

func TestCheckDocker(t *testing.T) {
	p := newTestProvisioner(t) // skips if docker unavailable
	assert.NotNil(t, p.client)
}

func TestContainerIP(t *testing.T) {
	p := newTestProvisioner(t)
	name := containerName(t.Name())
	startAlpine(t, p, name)

	ip, err := p.containerIP(context.Background(), name)
	require.NoError(t, err)
	assert.NotEmpty(t, ip)
	assert.NotNil(t, net.ParseIP(ip), "expected a valid IP address, got %q", ip)
}

func TestClean(t *testing.T) {
	t.Run("removes containers listed as instances", func(t *testing.T) {
		p := newTestProvisioner(t)
		name := containerName(t.Name())
		startAlpine(t, p, name)

		require.True(t, containerExists(p, name), "container should exist before Clean")

		err := p.Clean(context.Background(), common.Config{}, []common.Instance{{Name: name}})
		require.NoError(t, err)

		assert.False(t, containerExists(p, name), "container should be removed after Clean")
	})

	t.Run("sweeps leftover containers by label", func(t *testing.T) {
		p := newTestProvisioner(t)
		name := containerName(t.Name())

		// Create a container with the provisioner label but do NOT include it in the
		// instances list — simulating a container from a run cancelled mid-provision.
		startAlpineLabeled(t, p, name)

		require.True(t, containerExists(p, name), "container should exist before Clean")

		// Clean with no instances: the label sweep must pick it up.
		err := p.Clean(context.Background(), common.Config{}, nil)
		require.NoError(t, err)

		assert.False(t, containerExists(p, name), "leftover container should be swept by Clean")
	})

	t.Run("sweeps leftover containers by name prefix", func(t *testing.T) {
		p := newTestProvisioner(t)
		// Build a name that carries the provisioner prefix but no containerLabel,
		// to exercise the name-prefix branch of the sweep independently.
		name := containerName(t.Name())
		startAlpine(t, p, name)

		require.True(t, containerExists(p, name), "container should exist before Clean")

		err := p.Clean(context.Background(), common.Config{}, nil)
		require.NoError(t, err)

		assert.False(t, containerExists(p, name), "prefix-matched leftover should be swept by Clean")
	})
}

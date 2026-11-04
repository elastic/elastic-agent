// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-sysinfo/types"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/hostinfo"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/ecsmeta"
)

func TestECSMetadata(t *testing.T) {
	agentInfo := new(AgentInfo)
	agentInfo.agentID = "fake-agent-id"
	agentInfo.logLevelPolicy = "trace"
	agentInfo.unprivileged = true

	l := testutils.NewErrorLogger(t)
	metadata, err := agentInfo.ECSMetadata(l)
	require.NoError(t, err)

	if assert.NotNil(t, metadata.Elastic, "metadata.Elastic must not be nil") {
		assert.NotNil(t, metadata.Elastic.Agent, "metadata.Elastic.Agent must not be nil")
	}

	host, err := hostinfo.Fetch(t.Context(), l)
	require.NoError(t, err)

	assert.Equal(t, agentInfo.agentID, metadata.Elastic.Agent.ID)
	assert.Equal(t, release.Version(), metadata.Elastic.Agent.Version)
	assert.Equal(t, release.Snapshot(), metadata.Elastic.Agent.Snapshot)
	assert.Equal(t, release.Complete(), metadata.Elastic.Agent.Complete)
	assert.Equal(t, release.Info().String(), metadata.Elastic.Agent.BuildOriginal)
	assert.Equal(t, release.Upgradeable() || (paths.RunningInstalled() && RunningUnderSupervisor()), metadata.Elastic.Agent.Upgradeable)
	assert.Equal(t, agentInfo.logLevelPolicy, metadata.Elastic.Agent.LogLevel)
	assert.Equal(t, agentInfo.unprivileged, metadata.Elastic.Agent.Unprivileged)
	assert.Equal(t, release.FIPSDistribution(), metadata.Elastic.Agent.FIPS)

	assert.Equal(t, NewECSMetadata(agentInfo, host).Host, metadata.Host)
	assert.Equal(t, NewECSMetadata(agentInfo, host).OS, metadata.OS)
}

func TestNewECSMetadata(t *testing.T) {
	agentInfo := new(AgentInfo)
	agentInfo.agentID = "fake-agent-id"
	host := hostinfo.Info{
		Hostname:      "My-Host.Example.com",
		ID:            "host-id",
		Architecture:  "x86_64",
		KernelVersion: "6.8.0",
		IPs:           []string{"10.0.0.1"},
		MACs:          []string{"00:00:00:00:00:01"},
		OS: types.OSInfo{
			Family:   "debian",
			Platform: "ubuntu",
			Name:     "Ubuntu",
			Version:  "24.04",
			Codename: "noble",
		},
		MemoryTotal: 1024,
	}

	metadata := NewECSMetadata(agentInfo, host)

	assert.Equal(t, "fake-agent-id", metadata.Elastic.Agent.ID)
	assert.Equal(t, &ecsmeta.HostECSMeta{
		Arch:     "x86_64",
		Hostname: "My-Host.Example.com",
		Name:     "my-host.example.com", // host.name is always lower-case
		ID:       "host-id",
		IP:       []string{"10.0.0.1"},
		MAC:      []string{"00:00:00:00:00:01"},
		Memory:   1024,
	}, metadata.Host)
	assert.Equal(t, &ecsmeta.SystemECSMeta{
		Family:   "debian",
		Kernel:   "6.8.0",
		Platform: "ubuntu",
		Version:  "24.04",
		Name:     "Ubuntu",
		FullName: "Ubuntu noble(24.04)",
	}, metadata.OS)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-sysinfo"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/internal/pkg/util"
	"github.com/elastic/elastic-agent/pkg/features"
)

func TestECSMetadata(t *testing.T) {
	agentInfo := new(AgentInfo)
	agentInfo.agentID = "fake-agent-id"
	agentInfo.logLevel = "trace"
	agentInfo.unprivileged = true

	l := testutils.NewErrorLogger(t)
	metadata, err := agentInfo.ECSMetadata(l)
	require.NoError(t, err)

	if assert.NotNil(t, metadata.Elastic, "metadata.Elastic must not be nil") {
		assert.NotNil(t, metadata.Elastic.Agent, "metadata.Elastic.Agent must not be nil")
	}

	sysInfo, err := sysinfo.Host()
	require.NoError(t, err)

	info := sysInfo.Info()
	hostname := util.GetHostName(features.FQDN(), info, sysInfo, l)

	assert.Equal(t, agentInfo.agentID, metadata.Elastic.Agent.ID)
	assert.Equal(t, release.Version(), metadata.Elastic.Agent.Version)
	assert.Equal(t, release.Snapshot(), metadata.Elastic.Agent.Snapshot)
	assert.Equal(t, release.Complete(), metadata.Elastic.Agent.Complete)
	assert.Equal(t, release.Info().String(), metadata.Elastic.Agent.BuildOriginal)
	assert.Equal(t, release.Upgradeable() || (paths.RunningInstalled() && RunningUnderSupervisor()), metadata.Elastic.Agent.Upgradeable)
	assert.Equal(t, agentInfo.logLevel, metadata.Elastic.Agent.LogLevel)
	assert.Equal(t, agentInfo.unprivileged, metadata.Elastic.Agent.Unprivileged)

	assert.Equal(t, info.Architecture, metadata.Host.Arch)
	assert.Equal(t, hostname, metadata.Host.Hostname)
	assert.Equal(t, strings.ToLower(hostname), metadata.Host.Name) // host.name is always lower-case
	assert.Equal(t, info.UniqueID, metadata.Host.ID)
	assert.Equal(t, info.IPs, metadata.Host.IP)
	assert.Equal(t, info.MACs, metadata.Host.MAC)

	assert.Equal(t, info.OS.Family, metadata.OS.Family)
	assert.Equal(t, info.KernelVersion, metadata.OS.Kernel)
	assert.Equal(t, info.OS.Platform, metadata.OS.Platform)
	assert.Equal(t, info.OS.Version, metadata.OS.Version)
	assert.Equal(t, info.OS.Name, metadata.OS.Name)
	assert.Equal(t, getFullOSName(info), metadata.OS.FullName)
}

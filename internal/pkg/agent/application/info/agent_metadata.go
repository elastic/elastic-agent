// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/pkg/ecsmeta"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/hostinfo"
	"github.com/elastic/elastic-agent/internal/pkg/release"

	"github.com/elastic/go-sysinfo/types"
)

// Metadata loads metadata from disk, with the host information from hostInfo.
func Metadata(ctx context.Context, hostInfo hostinfo.Source) (*ecsmeta.ECSMeta, error) {
	agentInfo, err := NewAgentInfo(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create new agent info: %w", err)
	}

	host, err := hostInfo.Get(ctx)
	if err != nil {
		return nil, errors.New(err, "failed to gather host metadata")
	}

	return NewECSMetadata(agentInfo, host), nil
}

// NewECSMetadata returns the ECS compliant metadata of agent running on host.
func NewECSMetadata(agent Agent, host hostinfo.Info) *ecsmeta.ECSMeta {
	return &ecsmeta.ECSMeta{
		Elastic: &ecsmeta.ElasticECSMeta{
			Agent: &ecsmeta.AgentECSMeta{
				ID:            agent.AgentID(),
				Version:       release.Version(),
				Snapshot:      release.Snapshot(),
				Complete:      release.Complete(),
				BuildOriginal: release.Info().String(),
				// only upgradeable if running from Agent installer and running under the
				// control of the system supervisor (or built specifically with upgrading enabled)
				Upgradeable:  release.Upgradeable() || (paths.RunningInstalled() && RunningUnderSupervisor()),
				LogLevel:     agent.GetLogLevelRuntime(),
				Unprivileged: agent.Unprivileged(),
				FIPS:         release.FIPSDistribution(),
				Flavor:       installedFlavor(),
			},
		},
		Host: &ecsmeta.HostECSMeta{
			Arch:     host.Architecture,
			Hostname: host.Hostname,
			Name:     host.Name(),
			ID:       host.ID,
			IP:       host.IPs,
			MAC:      host.MACs,
			Memory:   host.MemoryTotal,
		},

		// Operating system
		OS: &ecsmeta.SystemECSMeta{
			Family:   host.OS.Family,
			Kernel:   host.KernelVersion,
			Platform: host.OS.Platform,
			Version:  host.OS.Version,
			Name:     host.OS.Name,
			FullName: getFullOSName(host.OS),
		},
	}
}

func getFullOSName(os types.OSInfo) string {
	var sb strings.Builder
	sb.WriteString(os.Name)
	if codeName := os.Codename; codeName != "" {
		sb.WriteString(" ")
		sb.WriteString(codeName)
	}

	if version := os.Version; version != "" {
		sb.WriteString("(")
		sb.WriteString(version)
		sb.WriteString(")")
	}

	return sb.String()
}

// defaultFlavor is the flavor reported when none was recorded at install time, for
// example an installation that predates flavors.
const defaultFlavor = "basic"

// installedFlavor returns the flavor reported to Fleet. A build of a dedicated flavor
// (such as edr) reports that flavor, otherwise it is the flavor recorded at install
// time, falling back to the default flavor when none was recorded.
func installedFlavor() string {
	if builtFlavor := release.Flavor(); builtFlavor != "" {
		return builtFlavor
	}
	content, err := os.ReadFile(filepath.Join(paths.Top(), paths.FlavorFileName))
	if err != nil {
		return defaultFlavor
	}
	if flavor := strings.TrimSpace(string(content)); flavor != "" {
		return flavor
	}
	return defaultFlavor
}

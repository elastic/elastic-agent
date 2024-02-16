// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/go-sysinfo"
)

// InjectAgentConfig injects config to a provided configuration.
func InjectAgentConfig(c *config.Config) error {
	globalConfig, err := agentGlobalConfig()
	if err != nil {
		return err
	}

	if err := c.Merge(globalConfig); err != nil {
		return errors.New("failed to inject agent global config", err, errors.TypeConfig)
	}

	return nil
}

// agentGlobalConfig gets global config used for resolution of variables inside configuration
// such as ${path.data}.
func agentGlobalConfig() (map[string]interface{}, error) {
	hostInfo, err := sysinfo.Host()
	if err != nil {
		return nil, err
	}

	nativeArch := hostInfo.Info().NativeArchitecture
	if nativeArch == "x86_64" {
		nativeArch = "amd64"
	}
	if nativeArch == "aarch64" {
		nativeArch = "arm64"
	}

	return map[string]interface{}{
		"path": map[string]interface{}{
			"data":   paths.Data(),
			"config": paths.Config(),
			"home":   paths.Home(),
			"logs":   paths.Logs(),
		},
		"host": map[string]interface{}{
			"id": hostInfo.Info().UniqueID,
		},
		"runtime.os":             runtime.GOOS,
		"runtime.arch":           runtime.GOARCH,
		"runtime.native_arch":    nativeArch,
		"runtime.osinfo.type":    hostInfo.Info().OS.Type,
		"runtime.osinfo.family":  hostInfo.Info().OS.Family,
		"runtime.osinfo.version": hostInfo.Info().OS.Version,
		"runtime.osinfo.major":   hostInfo.Info().OS.Major,
		"runtime.osinfo.minor":   hostInfo.Info().OS.Minor,
		"runtime.osinfo.patch":   hostInfo.Info().OS.Patch,
	}, nil
}

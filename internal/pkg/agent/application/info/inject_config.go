// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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

	return map[string]interface{}{
		"path": map[string]interface{}{
			"data":   paths.Data(),
			"config": paths.Config(),
			"home":   paths.Home(),
			"logs":   paths.Logs(),
		},
		"runtime.os":             runtime.GOOS,
		"runtime.arch":           runtime.GOARCH,
		"runtime.osinfo.type":    hostInfo.Info().OS.Type,
		"runtime.osinfo.family":  hostInfo.Info().OS.Family,
		"runtime.osinfo.version": hostInfo.Info().OS.Version,
		"runtime.osinfo.major":   hostInfo.Info().OS.Major,
		"runtime.osinfo.minor":   hostInfo.Info().OS.Minor,
		"runtime.osinfo.patch":   hostInfo.Info().OS.Patch,
	}, nil
}

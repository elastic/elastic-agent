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

package agent

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

func init() {
	composable.Providers.AddContextProvider("agent", ContextProviderBuilder)
}

type contextProvider struct{}

// Run runs the Agent context provider.
func (*contextProvider) Run(comm corecomp.ContextProviderComm) error {
	a, err := info.NewAgentInfo(false)
	if err != nil {
		return err
	}
	err = comm.Set(map[string]interface{}{
		"id": a.AgentID(),
		"version": map[string]interface{}{
			"version":    release.Version(),
			"commit":     release.Commit(),
			"build_time": release.BuildTime().Format("2006-01-02 15:04:05 -0700 MST"),
			"snapshot":   release.Snapshot(),
		},
	})
	if err != nil {
		return errors.New(err, "failed to set mapping", errors.TypeUnexpected)
	}
	return nil
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(_ *logger.Logger, _ *config.Config) (corecomp.ContextProvider, error) {
	return &contextProvider{}, nil
}

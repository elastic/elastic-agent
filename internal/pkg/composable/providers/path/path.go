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

package path

import (
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/internal/pkg/composable"
	"github.com/elastic/elastic-agent-poc/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent-poc/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
)

func init() {
	composable.Providers.AddContextProvider("path", ContextProviderBuilder)
}

type contextProvider struct{}

// Run runs the Agent context provider.
func (*contextProvider) Run(comm corecomp.ContextProviderComm) error {
	err := comm.Set(map[string]interface{}{
		"home":   paths.Home(),
		"data":   paths.Data(),
		"config": paths.Config(),
		"logs":   paths.Logs(),
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

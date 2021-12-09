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

package emitter

import (
	"context"
	"strings"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/application/info"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/application/pipeline"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/capabilities"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/composable"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/config"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
)

// New creates a new emitter function.
func New(ctx context.Context, log *logger.Logger, agentInfo *info.AgentInfo, controller composable.Controller, router pipeline.Router, modifiers *pipeline.ConfigModifiers, caps capabilities.Capability, reloadables ...reloadable) (pipeline.EmitterFunc, error) {
	log.Debugf("Supported programs: %s", strings.Join(program.KnownProgramNames(), ", "))

	ctrl := NewController(log, agentInfo, controller, router, modifiers, caps, reloadables...)
	err := controller.Run(ctx, func(vars []*transpiler.Vars) {
		ctrl.Set(vars)
	})
	if err != nil {
		return nil, errors.New(err, "failed to start composable controller")
	}
	return func(c *config.Config) error {
		return ctrl.Update(c)
	}, nil
}

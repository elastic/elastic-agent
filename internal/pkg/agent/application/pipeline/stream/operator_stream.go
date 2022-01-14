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

package stream

import (
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/application/pipeline"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/configrequest"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/state"
)

type operatorStream struct {
	configHandler pipeline.ConfigHandler
	log           *logger.Logger
}

type stater interface {
	State() map[string]state.State
}

type specer interface {
	Specs() map[string]program.Spec
}

func (b *operatorStream) Close() error {
	return b.configHandler.Close()
}

func (b *operatorStream) State() map[string]state.State {
	if s, ok := b.configHandler.(stater); ok {
		return s.State()
	}

	return nil
}

func (b *operatorStream) Specs() map[string]program.Spec {
	if s, ok := b.configHandler.(specer); ok {
		return s.Specs()
	}
	return nil
}

func (b *operatorStream) Execute(cfg configrequest.Request) error {
	return b.configHandler.HandleConfig(cfg)
}

func (b *operatorStream) Shutdown() {
	b.configHandler.Shutdown()
}

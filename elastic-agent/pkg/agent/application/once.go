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

package application

import (
	"context"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/application/pipeline"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/config"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
)

type once struct {
	log      *logger.Logger
	discover discoverFunc
	loader   *config.Loader
	emitter  pipeline.EmitterFunc
}

func newOnce(log *logger.Logger, discover discoverFunc, loader *config.Loader, emitter pipeline.EmitterFunc) *once {
	return &once{log: log, discover: discover, loader: loader, emitter: emitter}
}

func (o *once) Start() error {
	files, err := o.discover()
	if err != nil {
		return errors.New(err, "could not discover configuration files", errors.TypeConfig)
	}

	if len(files) == 0 {
		return ErrNoConfiguration
	}

	return readfiles(context.Background(), files, o.loader, o.emitter)
}

func (o *once) Stop() error {
	return nil
}

func readfiles(ctx context.Context, files []string, loader *config.Loader, emitter pipeline.EmitterFunc) error {
	c, err := loader.Load(files)
	if err != nil {
		return errors.New(err, "could not load or merge configuration", errors.TypeConfig)
	}

	return emitter(c)
}

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
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/pipeline"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/operation"
	"github.com/elastic/elastic-agent/internal/pkg/agent/stateresolver"
	downloader "github.com/elastic/elastic-agent/internal/pkg/artifact/download/localremote"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/install"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/uninstall"
	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/core/server"
	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

// Factory creates a new stream factory.
func Factory(ctx context.Context, agentInfo *info.AgentInfo, cfg *configuration.SettingsConfig, srv *server.Server, r state.Reporter, m monitoring.Monitor, statusController status.Controller) func(*logger.Logger, pipeline.RoutingKey) (pipeline.Stream, error) {
	return func(log *logger.Logger, id pipeline.RoutingKey) (pipeline.Stream, error) {
		// new operator per stream to isolate processes without using tags
		operator, err := newOperator(ctx, log, agentInfo, id, cfg, srv, r, m, statusController)
		if err != nil {
			return nil, err
		}

		return &operatorStream{
			log:           log,
			configHandler: operator,
		}, nil
	}
}

func newOperator(
	ctx context.Context,
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	id pipeline.RoutingKey,
	config *configuration.SettingsConfig,
	srv *server.Server,
	r state.Reporter,
	m monitoring.Monitor,
	statusController status.Controller,
) (*operation.Operator, error) {
	fetcher, err := downloader.NewDownloader(log, config.DownloadConfig)
	if err != nil {
		return nil, err
	}

	allowEmptyPgp, pgp := release.PGP()
	verifier, err := downloader.NewVerifier(log, config.DownloadConfig, allowEmptyPgp, pgp)
	if err != nil {
		return nil, errors.New(err, "initiating verifier")
	}

	installer, err := install.NewInstaller(config.DownloadConfig)
	if err != nil {
		return nil, errors.New(err, "initiating installer")
	}

	uninstaller, err := uninstall.NewUninstaller()
	if err != nil {
		return nil, errors.New(err, "initiating uninstaller")
	}

	stateResolver, err := stateresolver.NewStateResolver(log)
	if err != nil {
		return nil, err
	}

	return operation.NewOperator(
		ctx,
		log,
		agentInfo,
		id,
		config,
		fetcher,
		verifier,
		installer,
		uninstaller,
		stateResolver,
		srv,
		r,
		m,
		statusController,
	)
}

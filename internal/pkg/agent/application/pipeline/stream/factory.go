// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

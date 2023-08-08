// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type once struct {
	log      *logger.Logger
	discover config.DiscoverFunc
	loader   *config.Loader
	ch       chan coordinator.ConfigChange
	errCh    chan error
}

func newOnce(log *logger.Logger, discover config.DiscoverFunc, loader *config.Loader) *once {
	return &once{log: log, discover: discover, loader: loader, ch: make(chan coordinator.ConfigChange), errCh: make(chan error)}
}

func (o *once) Run(ctx context.Context) error {
	files, err := o.discover()
	if err != nil {
		return errors.New(err, "could not discover configuration files", errors.TypeConfig)
	}

	if len(files) == 0 {
		return config.ErrNoConfiguration
	}

	cfg, err := readfiles(files, o.loader)
	if err != nil {
		return err
	}
	o.ch <- &localConfigChange{cfg}
	<-ctx.Done()
	return ctx.Err()
}

func (o *once) Errors() <-chan error {
	return o.errCh
}

// ActionErrors returns the error channel for actions.
// Returns nil channel.
func (o *once) ActionErrors() <-chan error {
	return nil
}

func (o *once) Watch() <-chan coordinator.ConfigChange {
	return o.ch
}

func readfiles(files []string, loader *config.Loader) (*config.Config, error) {
	c, err := loader.Load(files)
	if err != nil {
		return nil, fmt.Errorf("failed to load or merge configuration: %w", err)
	}
	return c, nil
}

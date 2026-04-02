// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var _ coordinator.ConfigManager = &encryptedOnce{}

type encryptedOnce struct {
	log   *logger.Logger
	path  string
	ch    chan coordinator.ConfigChange
	errCh chan error
}

func newEncryptedOnce(log *logger.Logger, path string) *encryptedOnce {
	return &encryptedOnce{
		log:   log,
		path:  path,
		ch:    make(chan coordinator.ConfigChange),
		errCh: make(chan error),
	}
}

func (e *encryptedOnce) Run(ctx context.Context) error {
	store, err := storage.NewEncryptedDiskStore(ctx, e.path)
	if err != nil {
		return fmt.Errorf("unable to instantiate encrypted disk store: %w", err)
	}

	reader, err := store.Load()
	if err != nil {
		return fmt.Errorf("unable to load encrypted disk store: %w", err)
	}

	rawConfig, err := config.NewConfigFrom(reader)
	if err != nil {
		return fmt.Errorf("unable to read encrypted config: %w", err)
	}
	e.ch <- &localConfigChange{rawConfig}
	<-ctx.Done()
	return ctx.Err()
}

func (e *encryptedOnce) Errors() <-chan error {
	return e.errCh
}

func (*encryptedOnce) ActionErrors() <-chan error {
	return nil
}

func (e *encryptedOnce) Watch() <-chan coordinator.ConfigChange {
	return e.ch
}

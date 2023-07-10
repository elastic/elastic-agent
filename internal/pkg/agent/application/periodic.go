// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/filewatcher"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type periodic struct {
	log      *logger.Logger
	period   time.Duration
	watcher  *filewatcher.Watch
	loader   *config.Loader
	discover config.DiscoverFunc
	ch       chan coordinator.ConfigChange
	errCh    chan error
}

func (p *periodic) Run(ctx context.Context) error {
	if err := p.work(ctx); err != nil {
		return err
	}

	t := time.NewTicker(p.period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}

		if err := p.work(ctx); err != nil {
			return err
		}
	}
}

func (p *periodic) Errors() <-chan error {
	return p.errCh
}

// ActionErrors returns the error channel for actions.
// Returns nil channel.
func (p *periodic) ActionErrors() <-chan error {
	return nil
}

func (p *periodic) Watch() <-chan coordinator.ConfigChange {
	return p.ch
}

func (p *periodic) work(ctx context.Context) error {
	files, err := p.discover()
	if err != nil {
		return errors.New(err, "could not discover configuration files", errors.TypeConfig)
	}

	if len(files) == 0 {
		return config.ErrNoConfiguration
	}

	// Reset the state of the watched files
	p.watcher.Reset()

	p.log.Debugf("Adding %d file to watch", len(files))
	// Add any found files to the watchers
	for _, f := range files {
		p.watcher.Watch(f)
	}

	// Check for the following:
	// - Watching of new files.
	// - Files watched but some of them have changed.
	// - Files that we were watching but are not watched anymore.
	s, err := p.watcher.Update()
	if err != nil {
		return errors.New(err, "could not update the configuration states", errors.TypeConfig)
	}

	if s.NeedUpdate {
		p.log.Info("Configuration changes detected")
		if len(s.Unwatched) > 0 {
			p.log.Debugf("Unwatching %d files: %s", len(s.Unwatched), strings.Join(s.Unwatched, ", "))
		}

		if len(s.Updated) > 0 {
			p.log.Debugf("Updated %d files: %s", len(s.Updated), strings.Join(s.Updated, ", "))
		}

		if len(s.Unchanged) > 0 {
			p.log.Debugf("Unchanged %d files: %s", len(s.Unchanged), strings.Join(s.Updated, ", "))
		}

		cfg, err := readfiles(files, p.loader)
		if err != nil {
			// assume something when really wrong and invalidate any cache
			// so we get a full new config on next tick.
			p.watcher.Invalidate()
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p.ch <- &localConfigChange{cfg}:
		}

		return nil
	}

	p.log.Debug("No configuration change")
	return nil
}

func newPeriodic(
	log *logger.Logger,
	period time.Duration,
	discover config.DiscoverFunc,
	loader *config.Loader,
) *periodic {
	w, err := filewatcher.New(log, filewatcher.DefaultComparer)

	// this should not happen.
	if err != nil {
		panic(err)
	}

	return &periodic{
		log:      log,
		period:   period,
		watcher:  w,
		discover: discover,
		loader:   loader,
		ch:       make(chan coordinator.ConfigChange),
		errCh:    make(chan error),
	}
}

type localConfigChange struct {
	cfg *config.Config
}

func (l *localConfigChange) Config() *config.Config {
	return l.cfg
}

func (l *localConfigChange) Ack() error {
	// do nothing
	return nil
}

func (l *localConfigChange) Fail(_ error) {
	// do nothing
}

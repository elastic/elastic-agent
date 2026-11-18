// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package host

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/internal/pkg/hostinfo"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type contextProvider struct {
	logger *logger.Logger

	CheckInterval time.Duration `config:"check_interval"`

	// used by testing
	fetcher hostinfo.FetchFunc
}

// Run runs the environment context provider.
func (c *contextProvider) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	// The check interval is configurable, so the provider has its own watcher instead of sharing the agent's.
	watcher := hostinfo.NewWatcherWithFetcher(c.logger, c.CheckInterval, c.fetcher)
	watchCtx, cancel := context.WithCancel(comm)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() {
		if err := watcher.Run(watchCtx); err != nil && watchCtx.Err() == nil {
			c.logger.Errorf("Failed watching host information: %s", err)
		}
	})

	changed := watcher.Changed()
	info, err := watcher.Get(comm)
	if err != nil {
		return err
	}
	current := hostMapping(info)
	err = comm.Set(current)
	if err != nil {
		return errors.New(err, "failed to set mapping", errors.TypeUnexpected)
	}

	// Update context when any host information changes.
	for {
		select {
		case <-comm.Done():
			return comm.Err()
		case <-changed:
		}

		changed = watcher.Changed()
		info, err := watcher.Get(comm)
		if err != nil {
			c.logger.Warnf("Failed fetching latest host information: %s", err)
			continue
		}
		updated := hostMapping(info)
		if reflect.DeepEqual(current, updated) {
			// nothing to do
			continue
		}
		current = updated
		err = comm.Set(updated)
		if err != nil {
			c.logger.Errorf("Failed updating mapping to latest host information: %s", err)
		}
	}
}

func (c *contextProvider) Close() error {
	return nil
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(log *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	p := &contextProvider{
		logger: log,
		fetcher: func(context.Context) (hostinfo.Info, error) {
			return hostinfo.Fetch(log)
		},
	}
	if c != nil {
		err := c.UnpackTo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack config: %w", err)
		}
	}
	if p.CheckInterval <= 0 {
		p.CheckInterval = hostinfo.DefaultCheckInterval
	}

	return p, nil
}

func hostMapping(info hostinfo.Info) map[string]interface{} {
	return map[string]interface{}{
		"id": info.ID,
		// Lowercased even if it comes from ELASTIC_AGENT_HOSTNAME, unlike host.name in Beats events, see the
		// hostinfo package documentation.
		"name":         info.Name(),
		"platform":     runtime.GOOS,
		"architecture": info.Architecture,
		"ip":           info.IPs,
		"mac":          info.MACs,
		"os_family":    info.OS.Family,
		"os_platform":  info.OS.Platform,
		"os_version":   info.OS.Version,
	}
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package host

import (
	"fmt"
	"reflect"
	"runtime"
	"time"

	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/go-sysinfo"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// DefaultCheckInterval is the default timeout used to check if any host information has changed.
const DefaultCheckInterval = 5 * time.Minute

func init() {
	composable.Providers.MustAddContextProvider("host", ContextProviderBuilder)
}

type infoFetcher func() (map[string]interface{}, error)

type contextProvider struct {
	logger *logger.Logger

	CheckInterval time.Duration `config:"check_interval"`

	// used by testing
	fetcher infoFetcher
}

// Run runs the environment context provider.
func (c *contextProvider) Run(comm corecomp.ContextProviderComm) error {
	current, err := c.fetcher()
	if err != nil {
		return err
	}
	err = comm.Set(current)
	if err != nil {
		return errors.New(err, "failed to set mapping", errors.TypeUnexpected)
	}

	const fqdnFeatureFlagCallbackID = "host_provider"
	fqdnFFChangeCh := make(chan struct{})
	err = features.AddFQDNOnChangeCallback(
		onFQDNFeatureFlagChange(fqdnFFChangeCh),
		fqdnFeatureFlagCallbackID,
	)
	if err != nil {
		return fmt.Errorf("unable to add FQDN onChange callback in host provider: %w", err)
	}

	defer func() {
		features.RemoveFQDNOnChangeCallback(fqdnFeatureFlagCallbackID)
		close(fqdnFFChangeCh)
	}()

	// Update context when any host information changes.
	for {
		t := time.NewTimer(c.CheckInterval)
		select {
		case <-comm.Done():
			t.Stop()
			return comm.Err()
		case <-fqdnFFChangeCh:
		case <-t.C:
		}

		updated, err := c.fetcher()
		if err != nil {
			c.logger.Warnf("Failed fetching latest host information: %s", err)
			continue
		}
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

func onFQDNFeatureFlagChange(fqdnFFChangeCh chan struct{}) features.BoolValueOnChangeCallback {
	return func(new, old bool) {
		// FQDN feature flag was toggled, so notify on channel
		fqdnFFChangeCh <- struct{}{}
	}
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(log *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	p := &contextProvider{
		logger:  log,
		fetcher: getHostInfo(log),
	}
	if c != nil {
		err := c.Unpack(p)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack config: %w", err)
		}
	}
	if p.CheckInterval <= 0 {
		p.CheckInterval = DefaultCheckInterval
	}
	return p, nil
}

func getHostInfo(log *logger.Logger) func() (map[string]interface{}, error) {
	return func() (map[string]interface{}, error) {
		sysInfo, err := sysinfo.Host()
		if err != nil {
			return nil, err
		}

		info := sysInfo.Info()
		name := info.Hostname
		if features.FQDN() {
			fqdn, err := sysInfo.FQDN()
			if err != nil {
				log.Debugf("unable to lookup FQDN: %s, using hostname = %s", err.Error(), name)
			} else {
				name = fqdn
			}
		}

		return map[string]interface{}{
			"id":           info.UniqueID,
			"name":         name,
			"platform":     runtime.GOOS,
			"architecture": info.Architecture,
			"ip":           info.IPs,
			"mac":          info.MACs,
		}, nil
	}
}

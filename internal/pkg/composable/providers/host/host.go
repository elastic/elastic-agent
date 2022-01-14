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

package host

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"time"

	"github.com/elastic/go-sysinfo"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/internal/pkg/composable"
	"github.com/elastic/elastic-agent-poc/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent-poc/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
)

// DefaultCheckInterval is the default timeout used to check if any host information has changed.
const DefaultCheckInterval = 5 * time.Minute

func init() {
	composable.Providers.AddContextProvider("host", ContextProviderBuilder)
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

	// Update context when any host information changes.
	go func() {
		for {
			t := time.NewTimer(c.CheckInterval)
			select {
			case <-comm.Done():
				t.Stop()
				return
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
	}()

	return nil
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(log *logger.Logger, c *config.Config) (corecomp.ContextProvider, error) {
	p := &contextProvider{
		logger:  log,
		fetcher: getHostInfo,
	}
	if c != nil {
		err := c.Unpack(p)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack config: %s", err)
		}
	}
	if p.CheckInterval <= 0 {
		p.CheckInterval = DefaultCheckInterval
	}
	return p, nil
}

func getHostInfo() (map[string]interface{}, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	sysInfo, err := sysinfo.Host()
	if err != nil {
		return nil, err
	}
	info := sysInfo.Info()
	return map[string]interface{}{
		"id":           info.UniqueID,
		"name":         hostname,
		"platform":     runtime.GOOS,
		"architecture": info.Architecture,
		"ip":           info.IPs,
		"mac":          info.MACs,
	}, nil
}

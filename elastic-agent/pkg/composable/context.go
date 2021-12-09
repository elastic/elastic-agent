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

package composable

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/config"
	corecomp "github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/composable"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
)

// ContextProviderBuilder creates a new context provider based on the given config and returns it.
type ContextProviderBuilder func(log *logger.Logger, config *config.Config) (corecomp.ContextProvider, error)

// AddContextProvider adds a new ContextProviderBuilder
func (r *providerRegistry) AddContextProvider(name string, builder ContextProviderBuilder) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if name == "" {
		return fmt.Errorf("provider name is required")
	}
	if strings.ToLower(name) != name {
		return fmt.Errorf("provider name must be lowercase")
	}
	_, contextExists := r.contextProviders[name]
	_, dynamicExists := r.dynamicProviders[name]
	if contextExists || dynamicExists {
		return fmt.Errorf("provider '%s' is already registered", name)
	}
	if builder == nil {
		return fmt.Errorf("provider '%s' cannot be registered with a nil factory", name)
	}

	r.contextProviders[name] = builder
	r.logger.Debugf("Registered provider: %s", name)
	return nil
}

// GetContextProvider returns the context provider with the giving name, nil if it doesn't exist
func (r *providerRegistry) GetContextProvider(name string) (ContextProviderBuilder, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	b, ok := r.contextProviders[name]
	return b, ok
}

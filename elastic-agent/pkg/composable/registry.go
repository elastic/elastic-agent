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
	"sync"

	"github.com/elastic/beats/v7/libbeat/logp"
)

// providerRegistry is a registry of providers
type providerRegistry struct {
	contextProviders map[string]ContextProviderBuilder
	dynamicProviders map[string]DynamicProviderBuilder

	logger *logp.Logger
	lock   sync.RWMutex
}

// Providers holds all known providers, they must be added to it to enable them for use
var Providers = &providerRegistry{
	contextProviders: make(map[string]ContextProviderBuilder),
	dynamicProviders: make(map[string]DynamicProviderBuilder),
	logger:           logp.NewLogger("dynamic"),
}

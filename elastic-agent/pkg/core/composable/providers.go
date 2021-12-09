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

import "context"

// FetchContextProvider is the interface that a context provider uses so as to be able to be called
// explicitely on demand by vars framework in order to fetch specific target values like a k8s secret.
type FetchContextProvider interface {
	ContextProvider
	// Run runs the inventory provider.
	Fetch(string) (string, bool)
}

// ContextProviderComm is the interface that a context provider uses to communicate back to Elastic Agent.
type ContextProviderComm interface {
	context.Context

	// Set sets the current mapping for this context.
	Set(map[string]interface{}) error
}

// ContextProvider is the interface that a context provider must implement.
type ContextProvider interface {
	// Run runs the context provider.
	Run(ContextProviderComm) error
}

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

package fleet

import (
	"context"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/fleetapi"
)

// Acker is a noop acker.
// Methods of these acker do nothing.
type Acker struct{}

// NewAcker creates a new noop acker.
func NewAcker() *Acker {
	return &Acker{}
}

// Ack acknowledges action.
func (f *Acker) Ack(ctx context.Context, action fleetapi.Action) error {
	return nil
}

// Commit commits ack actions.
func (*Acker) Commit(ctx context.Context) error { return nil }

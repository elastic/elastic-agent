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

package handlers

import (
	"context"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/fleetapi"
)

// Default is a default handler.
type Default struct {
	log *logger.Logger
}

// NewDefault creates a new Default handler.
func NewDefault(log *logger.Logger) *Default {
	return &Default{
		log: log,
	}
}

// Handle is a default handler, no action is taken.
func (h *Default) Handle(_ context.Context, a fleetapi.Action, acker store.FleetAcker) error {
	h.log.Errorf("HandlerDefault: action '%+v' received", a)
	return nil
}

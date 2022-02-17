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
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

// Upgrade is a handler for UPGRADE action.
// After running Upgrade agent should download its own version specified by action
// from repository specified by fleet.
type Upgrade struct {
	log      *logger.Logger
	upgrader *upgrade.Upgrader
}

// NewUpgrade creates a new Upgrade handler.
func NewUpgrade(log *logger.Logger, upgrader *upgrade.Upgrader) *Upgrade {
	return &Upgrade{
		log:      log,
		upgrader: upgrader,
	}
}

// Handle handles UPGRADE action.
func (h *Upgrade) Handle(ctx context.Context, a fleetapi.Action, acker store.FleetAcker) error {
	h.log.Debugf("handlerUpgrade: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUpgrade)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUpgrade and received %T", a)
	}

	_, err := h.upgrader.Upgrade(ctx, &upgradeAction{action}, true)
	return err
}

type upgradeAction struct {
	*fleetapi.ActionUpgrade
}

func (a *upgradeAction) Version() string {
	return a.ActionUpgrade.Version
}

func (a *upgradeAction) SourceURI() string {
	return a.ActionUpgrade.SourceURI
}

func (a *upgradeAction) FleetAction() *fleetapi.ActionUpgrade {
	return a.ActionUpgrade
}

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

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/fleetapi"
)

// PolicyReassign handles policy reassign change coming from fleet.
type PolicyReassign struct {
	log *logger.Logger
}

// NewPolicyReassign creates a new PolicyReassign handler.
func NewPolicyReassign(log *logger.Logger) *PolicyReassign {
	return &PolicyReassign{
		log: log,
	}
}

// Handle handles POLICY_REASSIGN action.
func (h *PolicyReassign) Handle(ctx context.Context, a fleetapi.Action, acker store.FleetAcker) error {
	h.log.Debugf("handlerPolicyReassign: action '%+v' received", a)

	if err := acker.Ack(ctx, a); err != nil {
		h.log.Errorf("failed to acknowledge POLICY_REASSIGN action with id '%s'", a.ID)
	} else if err := acker.Commit(ctx); err != nil {
		h.log.Errorf("failed to commit acker after acknowledging action with id '%s'", a.ID)
	}

	return nil
}

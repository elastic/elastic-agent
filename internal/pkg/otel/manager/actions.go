// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/pkg/component"
)

// PerformAction routes a Fleet action to the beat receiver instance backing
// comp, which must be running under the OTel runtime. The action is delivered
// through the elasticdiagnostics extension over its Unix socket (see
// otel.PerformActionExt); the receiver's registered action handler runs the
// action and this returns its result.
func (m *OTelManager) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	return otel.PerformActionExt(ctx, comp.ID, name, params)
}

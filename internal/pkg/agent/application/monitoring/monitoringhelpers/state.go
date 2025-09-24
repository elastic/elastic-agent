// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoringhelpers

import (
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

// HaveState returns true if any of the components or any of its units has the given state
func HaveState(components []runtime.ComponentComponentState, state client.UnitState) bool {
	for _, component := range components {
		if component.State.State == state {
			return true
		}
		for _, unit := range component.State.Units {
			if unit.State == state {
				return true
			}
		}
	}
	return false
}

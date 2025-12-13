// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package capabilities

import "github.com/elastic/elastic-agent/pkg/core/logger"

type fleetOverrideCapability struct {
	// Whether a successful condition check lets an upgrade proceed or blocks it
	rule allowOrDeny
}

func newFleetOverrideCapability(rule allowOrDeny) *fleetOverrideCapability {
	return &fleetOverrideCapability{
		rule: rule,
	}
}

func allowFleetOverride(
	log *logger.Logger,
	fleetOverrideCaps []*fleetOverrideCapability,
) bool {
	// first match wins
	for _, cap := range fleetOverrideCaps {
		if cap == nil {
			// being defensive here, should not happen
			continue
		}

		switch cap.rule {
		case ruleTypeAllow:
			log.Debugf("Fleet override allowed by capability")
			return true
		case ruleTypeDeny:
			log.Debugf("Fleet override denied by capability")
			return false
		}
	}
	// No matching capability found, disable by default
	return false
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/eql"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type upgradeCapability struct {
	// The condition that this constraint checks
	condition *eql.Expression

	// Whether a successful condition check lets an upgrade proceed or blocks it
	rule allowOrDeny

	// The original string used to create the EQL condition, preserved to allow
	// useful error reporting
	conditionStr string
}

func newUpgradeCapability(condition string, rule allowOrDeny) (*upgradeCapability, error) {
	sanitizedCond := condition
	if condition == "" {
		// empty string counts as always succeeding, but empty string is not
		// a valid EQL expression, so create it from the constant expression "true"
		sanitizedCond = "true"
	}
	eqlExpr, err := eql.New(sanitizedCond)
	if err != nil {
		return nil, fmt.Errorf("couldn't load upgrade condition %q: %w", condition, err)
	}
	return &upgradeCapability{
		condition:    eqlExpr,
		rule:         rule,
		conditionStr: condition,
	}, nil
}

// allowUpgrade checks the EQL conditions in the given upgrade capabilities
// giving them variable access to "version" and "sourceURI"
func allowUpgrade(
	log *logger.Logger,
	version string, sourceURI string,
	upgradeCaps []*upgradeCapability,
) bool {
	// create VarStore out of map
	varStore, err := transpiler.NewAST(map[string]interface{}{
		"version":   version,
		"sourceURI": sourceURI,
	})
	if err != nil {
		// This should never happen, since the variables we just created should
		// deterministically succeed. But if there is a mysterious encoding bug,
		// don't block upgrades.
		log.Errorf("failed creating a varStore for upgrade capability: %v", err)
		return true
	}

	for _, cap := range upgradeCaps {
		result, err := cap.condition.Eval(varStore, true)
		if err != nil {
			log.Errorf("failed evaluating eql formula %q, skipping: %v", cap.conditionStr, err)
			return true
		}
		if result && cap.rule == ruleTypeDeny {
			// This rule blocks the attempted upgrade
			return false
		}
		if !result && cap.rule == ruleTypeAllow {
			// An "allow" rule failed its check, this also blocks the upgrade.
			return false
		}
	}
	// If nothing blocked the upgrade, allow it.
	return true
}

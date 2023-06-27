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

// NewUpgradeCapability creates capability filter for upgrade.
// Available variables:
// - version
// - source_uri
func newUpgradesCapability(caps []*upgradeCapability) *multiUpgradeCapability {
	return &multiUpgradeCapability{caps: caps}
}

func (c *multiUpgradeCapability) allowUpgrade(version string, sourceURI string) bool {
	// create VarStore out of map
	varStore, err := transpiler.NewAST(map[string]interface{}{
		"version":   version,
		"sourceURI": sourceURI,
	})
	if err != nil {
		// This should never happen, since the variables we just created should
		// deterministically succeed. But if there is a mysterious encoding bug,
		// don't block upgrades.
		c.log.Errorf("failed creating a varStore for upgrade capability: %v", err)
		return true
	}

	for _, cap := range c.caps {
		// if eql is not parsed or defined, skip
		if cap.upgradeEql == nil {
			continue
		}
		result, err := cap.upgradeEql.Eval(varStore, true)
		if err != nil {
			c.log.Errorf("failed evaluating eql formula for capability '%s', skipping: %v", cap.name(), err)
			return true
		}
		if result {
			// Passed the check, now see if we're allowing or denying
			return cap.Type == allowKey
		}
	}
	// If nothing else took effect, default to allow.
	return true
}

type upgradeCapability struct {
	log  *logger.Logger
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	Type string `json:"rule" yaml:"rule"`
	// UpgradeEql is eql expression defining upgrade
	UpgradeEqlDefinition string `json:"upgrade" yaml:"upgrade"`

	upgradeEql *eql.Expression
}

func (c *upgradeCapability) name() string {
	if c.Name != "" {
		return c.Name
	}

	t := "A"
	if c.Type == denyKey {
		t = "D"
	}

	// e.g UA(*) or UD(7.*.*)
	c.Name = fmt.Sprintf("U%s(%s)", t, c.UpgradeEqlDefinition)
	return c.Name
}

type multiUpgradeCapability struct {
	log  *logger.Logger
	caps []*upgradeCapability
}

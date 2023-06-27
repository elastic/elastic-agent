// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package capabilities

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestUpgrade(t *testing.T) {
	t.Run("valid action - version match", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"${version} == '8.0.0'",
				ruleTypeAllow,
			),
		}
		assert.True(t, allowUpgrade(log, "8.0.0", "", caps))
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"${version} == '8.0.0'",
				ruleTypeDeny,
			),
		}
		assert.False(t, allowUpgrade(log, "8.0.0", "", caps))
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				// a strange test... this EQL check will always fail because
				// there is no wildcard detection in string equality, so it should
				// never block an upgrade.
				"${version} == '8.*.*'",
				ruleTypeDeny,
			),
		}
		assert.True(t, allowUpgrade(log, "8.0.0", "", caps))
	})

	t.Run("valid action - version mismmatch", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"${version} == '7.12.0'",
				ruleTypeAllow,
			),
		}
		assert.False(t, allowUpgrade(log, "8.0.0", "", caps))
	})

	t.Run("valid action - version bug allowed minor mismatch", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"match(${version}, '8.0.*')",
				ruleTypeAllow,
			),
		}
		assert.True(t, allowUpgrade(log, "8.0.0", "", caps))
		assert.False(t, allowUpgrade(log, "8.1.0", "", caps))
	})

	t.Run("valid action - version minor allowed major mismatch", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"match(${version}, '8.*.*')",
				ruleTypeAllow,
			),
		}
		assert.False(t, allowUpgrade(log, "7.157.0", "", caps))
	})

	t.Run("valid action - version minor allowed minor upgrade", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"match(${version}, '8.*.*')",
				ruleTypeAllow,
			),
		}
		assert.True(t, allowUpgrade(log, "8.2.0", "", caps))
	})

	t.Run("valid action - require trusted url", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"startsWith(${sourceURI}, 'https')",
				ruleTypeAllow,
			),
		}
		assert.True(t, allowUpgrade(log, "9.0.0", "https://artifacts.elastic.co", caps))
		assert.False(t, allowUpgrade(log, "9.0.0", "http://artifacts.elastic.co", caps))
	})
}

// Creates an upgrade capability with the given condition and rule,
// or panics. For use on known-good EQL expressions while creating test inputs.
func mustNewUpgradeCapability(condition string, rule allowOrDeny) *upgradeCapability {
	cap, err := newUpgradeCapability(condition, rule)
	if err != nil {
		panic(fmt.Sprintf("couldn't create upgrade capability: %v", err))
	}
	return cap
}

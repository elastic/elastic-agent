// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
		// allow version 7.12.0, reject anything else
		caps := []*upgradeCapability{
			mustNewUpgradeCapability("${version} == '7.12.0'", ruleTypeAllow),
			mustNewUpgradeCapability("", ruleTypeDeny),
		}
		assert.True(t, allowUpgrade(log, "7.12.0", "", caps))
		assert.False(t, allowUpgrade(log, "7.12.1", "", caps))
		assert.False(t, allowUpgrade(log, "8.0.0", "", caps))
	})

	t.Run("version bug allowed minor mismatch", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability("match(${version}, '8.0.*')", ruleTypeAllow),
			mustNewUpgradeCapability("", ruleTypeDeny),
		}
		assert.True(t, allowUpgrade(log, "8.0.0", "", caps))
		assert.True(t, allowUpgrade(log, "8.0.1", "", caps))
		assert.False(t, allowUpgrade(log, "8.1.0", "", caps))
	})

	t.Run("version minor allowed major mismatch", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability("match(${version}, '8.*.*')", ruleTypeAllow),
			mustNewUpgradeCapability("", ruleTypeDeny),
		}
		assert.True(t, allowUpgrade(log, "8.157.0", "", caps))
		assert.True(t, allowUpgrade(log, "8.0.123", "", caps))
		assert.True(t, allowUpgrade(log, "8.2.0", "", caps))
		assert.False(t, allowUpgrade(log, "7.157.0", "", caps))
	})

	t.Run("require trusted url", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability(
				"startsWith(${sourceURI}, 'https')",
				ruleTypeAllow,
			),
			mustNewUpgradeCapability("", ruleTypeDeny),
		}
		assert.True(t, allowUpgrade(log, "9.0.0", "https://artifacts.elastic.co", caps))
		assert.False(t, allowUpgrade(log, "9.0.0", "http://artifacts.elastic.co", caps))
	})

	t.Run("empty pattern allow", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability("", ruleTypeAllow),
		}
		assert.True(t, allowUpgrade(log, "9.0.0", "", caps))
	})

	t.Run("empty pattern deny", func(t *testing.T) {
		log := logger.NewWithoutConfig("testing")
		caps := []*upgradeCapability{
			mustNewUpgradeCapability("", ruleTypeDeny),
		}
		assert.False(t, allowUpgrade(log, "9.0.0", "", caps))
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

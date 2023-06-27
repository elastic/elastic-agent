// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpgrade(t *testing.T) {
	t.Run("valid action - version match", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "${version} == '8.0.0'",
				},
			},
		}
		assert.True(t, cap.allowUpgrade("8.0.0", ""))
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "deny",
					UpgradeEqlDefinition: "${version} == '8.0.0'",
				},
			},
		}
		assert.False(t, cap.allowUpgrade("8.0.0", ""))
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type: "deny",
					// a strange test... this EQL check will always fail because
					// there is no wildcard detection in that equality, so it should
					// never block an upgrade.
					UpgradeEqlDefinition: "${version} == '8.*.*'",
				},
			},
		}
		assert.True(t, cap.allowUpgrade("8.0.0", ""))
	})

	t.Run("valid action - version mismmatch", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "${version} == '7.12.0'",
				},
			},
		}
		assert.False(t, cap.allowUpgrade("8.0.0", ""))
	})

	t.Run("valid action - version bug allowed minor mismatch", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.0.*')",
				},
			},
		}
		assert.True(t, cap.allowUpgrade("8.0.0", ""))
		assert.False(t, cap.allowUpgrade("8.1.0", ""))
	})

	t.Run("valid action - version minor allowed major mismatch", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		assert.False(t, cap.allowUpgrade("7.157.0", ""))
	})

	t.Run("valid action - version minor allowed minor upgrade", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		assert.True(t, cap.allowUpgrade("8.2.0", ""))
	})

	t.Run("valid action - require trusted url", func(t *testing.T) {
		cap := multiUpgradeCapability{
			caps: []*upgradeCapability{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
				},
			},
		}
		assert.True(t, cap.allowUpgrade("9.0.0", "https://artifacts.elastic.co"))
		assert.False(t, cap.allowUpgrade("9.0.0", "http://artifacts.elastic.co"))
	})
}

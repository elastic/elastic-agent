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

package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/fleetapi"
)

func TestUpgrade(t *testing.T) {
	tr := &testReporter{}
	l, _ := logger.New("test", false)
	t.Run("invalid rule", func(t *testing.T) {
		r := &inputCapability{}
		cap, err := newUpgradeCapability(l, r, tr)
		assert.NoError(t, err, "no error expected")
		assert.Nil(t, cap, "cap should not be created")
	})

	t.Run("empty eql", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "",
				},
			},
		}

		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")
	})

	t.Run("valid action - version match", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "${version} == '8.0.0'",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.0.0"}
		outAfter, err := cap.Apply(ta)

		assert.NoError(t, err, "should not be failing")
		assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "deny",
					UpgradeEqlDefinition: "${version} == '8.0.0'",
				},
			},
		}

		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.0.0"}
		outAfter, err := cap.Apply(ta)

		assert.Error(t, err, "should fail")
		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - deny version match", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "deny",
					UpgradeEqlDefinition: "${version} == '8.*.*'",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "9.0.0"}
		outAfter, err := cap.Apply(ta)

		assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		assert.NoError(t, err, "should not fail")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version mismmatch", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "${version} == '7.12.0'",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.0.0"}
		outAfter, err := cap.Apply(ta)

		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Error(t, err, "should fail")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version bug allowed minor mismatch", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.0.*')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.1.0"}
		outAfter, err := cap.Apply(ta)

		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Error(t, err, "should fail")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version minor allowed major mismatch", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "7.157.0"}
		outAfter, err := cap.Apply(ta)

		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Error(t, err, "should fail")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid action - version minor allowed minor upgrade", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		ta := &testUpgradeAction{version: "8.2.0"}
		outAfter, err := cap.Apply(ta)

		assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		assert.NoError(t, err, "should not fail")
		assert.Equal(t, ta, outAfter)
	})

	t.Run("valid fleetatpi.action - version match", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			ActionID:   "",
			ActionType: "",
			Version:    "8.2.0",
			SourceURI:  "http://artifacts.elastic.co",
		}
		outAfter, err := cap.Apply(apiAction)

		assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		assert.NoError(t, err, "should not fail")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid fleetatpi.action - version mismmatch", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := &fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "http://artifacts.elastic.co",
		}
		outAfter, err := cap.Apply(apiAction)

		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Error(t, err, "should fail")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid fleetatpi.action - version mismmatch", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "match(${version}, '8.*.*')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "http://artifacts.elastic.co",
		}
		outAfter, err := cap.Apply(apiAction)

		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Error(t, err, "should fail")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid action - source uri trusted", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "https://artifacts.elastic.co",
		}
		outAfter, err := cap.Apply(apiAction)

		assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		assert.NoError(t, err, "should not fail")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("valid action - source uri untrusted", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionUpgrade{
			Version:   "9.0.0",
			SourceURI: "http://artifacts.elastic.co",
		}
		outAfter, err := cap.Apply(apiAction)

		assert.Equal(t, ErrBlocked, err, "should be blocking")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})

	t.Run("unknown action", func(t *testing.T) {
		rd := &ruleDefinitions{
			Capabilities: []ruler{
				&upgradeCapability{
					Type:                 "allow",
					UpgradeEqlDefinition: "startsWith(${source_uri}, 'https')",
				},
			},
		}
		cap, err := newUpgradesCapability(l, rd, tr)
		assert.NoError(t, err, "error not expected, provided eql is valid")
		assert.NotNil(t, cap, "cap should be created")

		apiAction := fleetapi.ActionPolicyChange{}
		outAfter, err := cap.Apply(apiAction)

		assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		assert.NoError(t, err, "should not fail")
		assert.Equal(t, apiAction, outAfter, "action should not be altered")
	})
}

type testUpgradeAction struct {
	version string
}

// Version to upgrade to.
func (a *testUpgradeAction) Version() string {
	return a.version
}

// SourceURI for download.
func (a *testUpgradeAction) SourceURI() string {
	return "http://artifacts.elastic.co"
}

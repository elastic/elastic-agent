// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // tests are not the same, just equivalent
package capabilities

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestFilterMetrics(t *testing.T) {
	yml := `
capabilities:
- rule: allow
  input: system/metrics
`
	caps, err := Load(strings.NewReader(yml), logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")

	assert.True(t, caps.AllowInput("system/metrics"))
	assert.True(t, caps.AllowInput("system/logs"))
	assert.True(t, caps.AllowOutput("elasticsearch"))
}

func TestAllowMetrics(t *testing.T) {
	yml := `
capabilities:
- rule: allow
  input: system/metrics
- rule: deny
  input: "*"
`
	caps, err := Load(strings.NewReader(yml), logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")

	assert.True(t, caps.AllowInput("system/metrics"))
	assert.False(t, caps.AllowInput("system/logs"))
	assert.True(t, caps.AllowOutput("elasticsearch"))
}

func TestDenyLogs(t *testing.T) {
	yml := `
capabilities:
- rule: deny
  input: system/logs
`
	caps, err := Load(strings.NewReader(yml), logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")

	assert.True(t, caps.AllowInput("system/metrics"))
	assert.False(t, caps.AllowInput("system/logs"))
	assert.True(t, caps.AllowOutput("elasticsearch"))
}

func TestDenyMetrics(t *testing.T) {
	yml := `
capabilities:
- rule: deny
  input: "*/metrics"
`

	caps, err := Load(strings.NewReader(yml), logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")

	assert.False(t, caps.AllowInput("system/metrics"))
	assert.False(t, caps.AllowInput("linux/metrics"))
	assert.False(t, caps.AllowInput("statsd/metrics"))
	assert.False(t, caps.AllowInput("gcp/metrics"))
	assert.True(t, caps.AllowInput("filestream"))
	assert.True(t, caps.AllowInput("cloudbeat/cis_aws"))
	assert.True(t, caps.AllowInput("synthetics/http"))
}

func TestUpgradeVersion(t *testing.T) {
	// Allow upgrades to 8.9.2 or any 8.8.x, deny all others
	yml := `
capabilities:
- upgrade: "match(${version}, '8.8.*')"
  rule: allow
- upgrade: "${version} == '8.9.2'"
  rule: allow
- upgrade:
  rule: deny
`

	caps, err := Load(strings.NewReader(yml), logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")
	assert.True(t, caps.AllowUpgrade("8.8.0", ""))
	assert.True(t, caps.AllowUpgrade("8.8.1", ""))
	assert.True(t, caps.AllowUpgrade("8.9.2", ""))
	assert.False(t, caps.AllowUpgrade("8.9.1", ""))
	assert.False(t, caps.AllowUpgrade("8.7.0", ""))
	assert.False(t, caps.AllowUpgrade("8.10.0", ""))

}

func TestNoCaps(t *testing.T) {
	// Make sure capabilities loaded from a nonexistent file don't interfere
	// with anything
	filename := filepath.Join("testdata", "nonexistent.yml")
	caps, err := LoadFile(filename, logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")

	assert.True(t, caps.AllowInput("system/metrics"))
	assert.True(t, caps.AllowInput("system/logs"))
	assert.True(t, caps.AllowOutput("elasticsearch"))
}

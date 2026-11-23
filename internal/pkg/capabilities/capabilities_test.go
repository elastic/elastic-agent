// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	assert.True(t, caps.AllowUpgrade("8.8.0", nil))
	assert.True(t, caps.AllowUpgrade("8.8.1", nil))
	assert.True(t, caps.AllowUpgrade("8.9.2", nil))
	assert.False(t, caps.AllowUpgrade("8.9.1", nil))
	assert.False(t, caps.AllowUpgrade("8.7.0", nil))
	assert.False(t, caps.AllowUpgrade("8.10.0", nil))

}

func TestUpgradeSources(t *testing.T) {
	// Allow upgrades only from sources starting with "https://good"
	yml := `
capabilities:
- upgrade: "startsWith(${sourceURI}, 'https://good')"
  rule: allow
- upgrade:
  rule: deny
`
	caps, err := Load(strings.NewReader(yml), logger.NewWithoutConfig("testing"))
	require.NoError(t, err, "Loading capabilities should succeed")

	assert.Equal(t, []string{"https://good1.abc.com", "https://good2.abc.com"}, caps.FilterUpgradeSources("8.8.0", []string{"https://good1.abc.com", "https://bad.abc.com", "https://good2.abc.com"}))
	assert.Empty(t, caps.FilterUpgradeSources("8.8.0", []string{"https://bad1.abc.com", "https://bad2.abc.com"}))
	assert.Empty(t, caps.FilterUpgradeSources("8.8.0", nil))

	assert.True(t, caps.AllowUpgrade("8.8.0", []string{"https://good.abc.com"}))
	assert.True(t, caps.AllowUpgrade("8.8.0", []string{"https://bad.abc.com", "https://good.abc.com"}),
		"AllowUpgrade should allow if any one of the sources is allowed")
	assert.False(t, caps.AllowUpgrade("8.8.0", []string{"https://bad.abc.com"}))
	assert.False(t, caps.AllowUpgrade("8.8.0", []string{"https://bad1.abc.com", "https://bad2.abc.com"}))
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

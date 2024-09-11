// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package v1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmptyManifest(t *testing.T) {
	m := NewManifest()
	assert.Equal(t, VERSION, m.Version)
	assert.Equal(t, ManifestKind, m.Kind)
}

func TestParseManifest(t *testing.T) {

	manifest := `
# version and kind to uniquely identify the schema
version: co.elastic.agent/v1
kind: PackageManifest

# description of the package itself
package:
  version: 8.12.0
  snapshot: false
  versioned-home: data/elastic-agent-4f2d39/
  # generic path mapping:
  # - key is a prefix representing a path relative to the top of the archive 
  # - value is the substitution to be applied when extracting the files
  path-mappings:
    - data/elastic-agent-4f2d39/ : data/elastic-agent-8.12.0/
      foo: bar
    - manifest.yaml : data/elastic-agent-8.12.0/manifest.yaml 
`
	m, err := ParseManifest(strings.NewReader(manifest))
	assert.NoError(t, err)
	assert.Equal(t, VERSION, m.Version)
	assert.Equal(t, ManifestKind, m.Kind)

	assert.Equal(t, m.Package.Version, "8.12.0")
	assert.Equal(t, m.Package.Snapshot, false)
	assert.Equal(t, m.Package.VersionedHome, "data/elastic-agent-4f2d39/")
	assert.Equal(t, m.Package.PathMappings, []map[string]string{{"data/elastic-agent-4f2d39/": "data/elastic-agent-8.12.0/", "foo": "bar"}, {"manifest.yaml": "data/elastic-agent-8.12.0/manifest.yaml"}})
}

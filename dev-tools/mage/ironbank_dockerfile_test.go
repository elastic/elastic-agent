// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ironbankDockerfileTemplate = "../packaging/templates/ironbank/Dockerfile.tmpl"

var dockerfileAddInstruction = regexp.MustCompile(`(?im)^\s*ADD\s`)

func renderIronbankDockerfile(t *testing.T, data map[string]interface{}) string {
	t.Helper()

	cfg, err := LoadSettings()
	require.NoError(t, err)

	dst := filepath.Join(t.TempDir(), "Dockerfile")
	require.NoError(t, ExpandFile(cfg, ironbankDockerfileTemplate, dst, data))

	out, err := os.ReadFile(dst)
	require.NoError(t, err)
	return string(out)
}

// TestIronbankDockerfileHasNoAdd guards the Dockerfile submitted to Ironbank.
// The template is shared with the public CI variant, but Ironbank prohibits ADD
// and a violation only shows up as a failed build in the dso.mil GitLab repo.
// Neither variant needs it: external resources reach the build context through
// COPY (Ironbank supplies them via the hardening manifest, mage package
// downloads them).
func TestIronbankDockerfileHasNoAdd(t *testing.T) {
	// Without this the checks below could pass vacuously if the pattern broke.
	require.Regexp(t, dockerfileAddInstruction, "FROM scratch\n  ADD https://example.com/x /x\n")
	require.NotRegexp(t, dockerfileAddInstruction, "COPY add-on /x\n# ADD is prohibited\n")

	tests := map[string]map[string]interface{}{
		// Mirrors the template data built by prepareIronbankBuild in magefile.go.
		"submission": {"MajorMinor": "9.6", "public_build": false},
		"public CI":  {"public_build": "true"},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			out := renderIronbankDockerfile(t, data)
			assert.NotRegexp(t, dockerfileAddInstruction, out,
				"%s must use COPY, not ADD, because the template is submitted to Ironbank", ironbankDockerfileTemplate)
		})
	}
}

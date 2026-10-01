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

// TestIronbankDockerfileSubmissionHasNoAdd guards the Dockerfile submitted to
// Ironbank. The template is shared with the public CI variant, which uses ADD,
// but Ironbank prohibits ADD and a violation only shows up as a failed build in
// the dso.mil GitLab repo. Anything Ironbank-incompatible must stay inside
// {{ if .public_build }} branches.
func TestIronbankDockerfileSubmissionHasNoAdd(t *testing.T) {
	t.Run("submission render has no ADD", func(t *testing.T) {
		// Mirrors the template data built by prepareIronbankBuild in magefile.go.
		out := renderIronbankDockerfile(t, map[string]interface{}{
			"MajorMinor":   "9.6",
			"public_build": false,
		})

		assert.NotRegexp(t, dockerfileAddInstruction, out,
			"the Dockerfile submitted to Ironbank must use COPY, not ADD; "+
				"keep ADD inside {{ if .public_build }} branches of %s", ironbankDockerfileTemplate)
	})

	// Without this the check above could pass vacuously, e.g. if the pattern
	// stopped matching or the public build stopped using ADD.
	t.Run("public CI render uses ADD", func(t *testing.T) {
		out := renderIronbankDockerfile(t, map[string]interface{}{
			"public_build": "true",
			"tinit_url":    "https://example.com/tini",
			"tinit_sha256": "tinitsha",
			"jq_url":       "https://example.com/jq",
			"jq_sha256":    "jqsha",
		})

		assert.Regexp(t, dockerfileAddInstruction, out)
	})
}

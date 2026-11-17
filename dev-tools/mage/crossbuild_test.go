// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheprogArgs(t *testing.T) {
	t.Run("disabled without a crossbuild dir", func(t *testing.T) {
		t.Setenv("CACHEPROG_CROSSBUILD_DIR", "")
		t.Setenv("GOCACHEPROG", "/tmp/cacheprog-wrapper")
		assert.Nil(t, cacheprogArgs())
	})

	t.Run("disabled without GOCACHEPROG", func(t *testing.T) {
		t.Setenv("CACHEPROG_CROSSBUILD_DIR", "/tmp/cacheprog")
		t.Setenv("GOCACHEPROG", "")
		assert.Nil(t, cacheprogArgs())
	})

	t.Run("forwards settings and credentials by name only", func(t *testing.T) {
		t.Setenv("CACHEPROG_CROSSBUILD_DIR", "/tmp/cacheprog")
		t.Setenv("GOCACHEPROG", "/tmp/cacheprog/cacheprog-wrapper")
		t.Setenv("CACHEPROG_ROOT_DIRECTORY", "/home/ci/.cache/cacheprog")
		t.Setenv("CACHEPROG_S3_BUCKET", "bucket")
		t.Setenv("CACHEPROG_DISABLE_PUT", "true")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")

		args := cacheprogArgs()
		require.NotEmpty(t, args)

		assert.Contains(t, args, "/tmp/cacheprog:/cacheprog")
		assert.Contains(t, args, "GOCACHEPROG=/cacheprog/cacheprog-wrapper-container")
		assert.Contains(t, args, "CACHEPROG_ROOT_DIRECTORY=/cacheprog/disk-container")
		// Settings and credentials are passed by name, so their values never
		// show up in the logged docker command line.
		assert.Contains(t, args, "CACHEPROG_S3_BUCKET")
		assert.Contains(t, args, "CACHEPROG_DISABLE_PUT")
		assert.Contains(t, args, "AWS_SECRET_ACCESS_KEY")
		for _, a := range args {
			assert.NotContains(t, a, "secret")
			assert.NotContains(t, a, "=bucket")
		}
		// The host-side paths must not override the container paths.
		assert.NotContains(t, args, "CACHEPROG_ROOT_DIRECTORY")
		assert.NotContains(t, args, "CACHEPROG_CROSSBUILD_DIR")
	})
}

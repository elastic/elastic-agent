// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/pprof/profile"
)

func TestGlobalHooks(t *testing.T) {
	hooks := GlobalHooks()
	assert.NotEmpty(t, hooks, "multiple hooks should be returned")
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(func() { cancel() })
	for _, h := range hooks {
		output := h.Hook(ctx)
		assert.NotEmpty(t, h, "hook should produce output")
		var ok bool
		var err error
		switch h.Name {
		case "version":
			ok, err = isVersion(output)
		default:
			ok, err = isPprof(output)
		}
		assert.Truef(t, ok, "hook: %s returned incompatible data, err: %s, data: %v ", h.Name, err, output)
	}
}

func isVersion(input []byte) (bool, error) {
	return strings.Contains(string(input), "version:"), nil
}

func isPprof(input []byte) (bool, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(input))
	if err != nil {
		return false, err
	}
	uncompressed, err := io.ReadAll(gz)
	if err != nil {
		return false, err
	}
	_, err = profile.ParseUncompressed(uncompressed)
	if err != nil {
		return false, err
	}
	return true, nil
}

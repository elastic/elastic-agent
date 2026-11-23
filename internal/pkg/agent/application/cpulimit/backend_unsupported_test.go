// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnsupportedBackend(t *testing.T) {
	b := NewUnsupportedBackend()
	ctx := t.Context()

	_, err := b.LogicalCPUs(ctx)
	require.True(t, isUnsupported(err))
	_, err = b.Inspect(ctx)
	require.True(t, isUnsupported(err))
	require.True(t, isUnsupported(b.Apply(ctx, 1)))
	require.True(t, isUnsupported(b.Remove(ctx)))
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGzipCopy checks that the parallel compressor used for the docker image
// archives produces a stream the standard gzip reader decodes back to the
// input, across block boundaries and for inputs smaller than one block.
func TestGzipCopy(t *testing.T) {
	for _, size := range []int{0, 1, 1 << 10, 1<<20 + 17, 5<<20 + 3} {
		input := make([]byte, size)
		_, err := rand.Read(input[:size/2])
		require.NoError(t, err)

		var compressed bytes.Buffer
		require.NoError(t, gzipCopy(&compressed, bytes.NewReader(input)))

		r, err := gzip.NewReader(&compressed)
		require.NoError(t, err)
		output, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.Equal(t, input, output, "round trip mismatch for %d bytes", size)
	}
}

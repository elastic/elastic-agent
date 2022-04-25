// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package id

import (
	"fmt"
	"testing"

	"github.com/oklog/ulid"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	var pre ulid.ULID

	for i := 0; i < 1000; i++ {
		id, err := Generate()
		require.NoError(t, err)
		require.NotNil(t, id)
		require.NotEqual(t, id, pre)
		pre = id
		fmt.Printf("%s--- %s\n", id, pre)
	}
}

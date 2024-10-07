// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOtelCommandIsNil(t *testing.T) {
	require.Nil(t, newOtelCommandWithArgs(nil, nil))
}

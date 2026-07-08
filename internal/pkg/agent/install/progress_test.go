// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProgressSpinner(t *testing.T) {
	stringWriter := &bytes.Buffer{}

	spinner := CreateAndStartNewSpinner(stringWriter, "example")

	spinner.Describe("test input")
	// Finish stops the internal render goroutine (added in progressbar v3.14+). After
	// Finish returns, state.finished=true and any pending render call exits early without
	// writing, so reading the buffer is race-free.
	require.NoError(t, spinner.Finish())

	res := stringWriter.String()
	require.Contains(t, res, "test input")
}

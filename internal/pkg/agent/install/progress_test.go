// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProgressSpinner(t *testing.T) {
	stringWriter := &bytes.Buffer{}

	spinner := CreateAndStartNewSpinner(stringWriter)

	spinner.Describe("test input")

	res := stringWriter.String()
	require.Contains(t, res, "test input")
}

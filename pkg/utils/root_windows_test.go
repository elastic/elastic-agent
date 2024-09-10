// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasRoot(t *testing.T) {
	t.Run("check if user is admin", func(t *testing.T) {
		_, err := HasRoot()
		assert.NoError(t, err)
	})
}

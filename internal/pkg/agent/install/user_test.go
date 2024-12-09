// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureRights(t *testing.T) {
	// no-op function testing for coverage
	assert.NoError(t, EnsureRights("custom"))
}

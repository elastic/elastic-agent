// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package stack

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStackUp(t *testing.T) {
	ctx := context.Background()
	err := Up(ctx, "8.3.0","")
	assert.NotNil(t, err)
}

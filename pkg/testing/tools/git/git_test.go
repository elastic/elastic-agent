// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package git

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetReleaseBranches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	branches, err := GetReleaseBranches(ctx)
	require.NoError(t, err)
	t.Log(branches)
	assert.NotEmpty(t, branches)
	for _, b := range branches {
		assert.Regexp(t, releaseBranchRegexp, b)
	}
}

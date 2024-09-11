// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
)

func TestContextProvider(t *testing.T) {
	testutils.InitStorage(t)

	builder, _ := composable.Providers.GetContextProvider("agent")
	provider, err := builder(nil, nil, true)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	comm := ctesting.NewContextComm(context.Background())
	err = provider.Run(ctx, comm)
	require.NoError(t, err)

	current := comm.Current()
	_, hasID := current["id"]
	assert.True(t, hasID, "missing id")
	_, hasVersion := current["version"]
	assert.True(t, hasVersion, "missing version")
	_, hasUnprivileged := current["unprivileged"]
	assert.True(t, hasUnprivileged, "missing unprivileged")
}

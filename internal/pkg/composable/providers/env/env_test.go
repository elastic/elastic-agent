// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package env

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
)

func TestContextProvider(t *testing.T) {
	builder, _ := composable.Providers.GetContextProvider("env")
	provider, err := builder(nil, nil, true)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	comm := ctesting.NewContextComm(ctx)
	err = provider.Run(ctx, comm)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	assert.Equal(t, getEnvMapping(), comm.Current())
}

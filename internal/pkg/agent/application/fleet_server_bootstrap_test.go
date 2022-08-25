// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
)

func TestFleetServerBootstrapManager(t *testing.T) {
	l := testutils.NewErrorLogger(t)
	mgr := newFleetServerBootstrapManager(l)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	g, _ := errgroup.WithContext(ctx)

	var change coordinator.ConfigChange
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-mgr.Errors():
				cancel()
				return err
			case change = <-mgr.Watch():
				cancel()
			}
		}
	})

	g.Go(func() error {
		return mgr.Run(ctx)
	})

	err := g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err)
	}

	require.NotNil(t, change)
	assert.NotNil(t, change.Config())
}

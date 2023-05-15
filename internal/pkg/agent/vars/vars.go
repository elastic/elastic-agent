// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vars

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func WaitForVariables(ctx context.Context, l *logger.Logger, cfg *config.Config, wait time.Duration) ([]*transpiler.Vars, error) {
	var cancel context.CancelFunc
	var vars []*transpiler.Vars

	composable, err := composable.New(l, cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create composable controller: %w", err)
	}
	defer composable.Close()

	hasTimeout := false
	if wait > time.Duration(0) {
		hasTimeout = true
		ctx, cancel = context.WithTimeout(ctx, wait)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		for {
			select {
			case <-ctx.Done():
				if err == nil {
					err = ctx.Err()
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					err = nil
				}
				return err
			case cErr := <-composable.Errors():
				err = cErr
				if err != nil {
					cancel()
				}
			case cVars := <-composable.Watch():
				vars = cVars
				if !hasTimeout {
					cancel()
				}
			}
		}
	})

	g.Go(func() error {
		err := composable.Run(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
		return err
	})

	err = g.Wait()
	if err != nil {
		return nil, err
	}
	return vars, nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package local

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func init() {
	composable.Providers.MustAddContextProvider("local", ContextProviderBuilder)
}

type contextProvider struct {
	Mapping map[string]interface{} `config:"vars"`
}

// Run runs the environment context provider.
func (c *contextProvider) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	err := comm.Set(c.Mapping)
	if err != nil {
		return errors.New(err, "failed to set mapping", errors.TypeUnexpected)
	}
	return nil
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(_ *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	p := &contextProvider{}
	if c != nil {
		err := c.Unpack(p)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack vars: %w", err)
		}
	}
	if p.Mapping == nil {
		p.Mapping = map[string]interface{}{}
	}
	return p, nil
}

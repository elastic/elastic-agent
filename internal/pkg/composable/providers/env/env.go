// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package env

import (
	"os"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func init() {
	composable.Providers.MustAddContextProvider("env", ContextProviderBuilder)
}

type contextProvider struct{}

// Run runs the environment context provider.
func (*contextProvider) Run(comm corecomp.ContextProviderComm) error {
	err := comm.Set(getEnvMapping())
	if err != nil {
		return errors.New(err, "failed to set mapping", errors.TypeUnexpected)
	}
	return nil
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(_ *logger.Logger, _ *config.Config, _ bool) (corecomp.ContextProvider, error) {
	return &contextProvider{}, nil
}

func getEnvMapping() map[string]interface{} {
	mapping := map[string]interface{}{}
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		mapping[pair[0]] = pair[1]
	}
	return mapping
}

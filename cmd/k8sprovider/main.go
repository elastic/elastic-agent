// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetes"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func main() {
	var mappings []composable.DynamicProviderMapping

	defaultCfg := logger.DefaultLoggingConfig()
	defaultCfg.Level = logp.DebugLevel
	defaultCfg.ToStderr = true

	defaultEventLogCfg := logger.DefaultEventLoggingConfig()
	baseLogger, err := logger.NewFromConfig("", defaultCfg, defaultEventLogCfg, false)
	if err != nil {
		panic(err)
	}

	baseLogger.Info("Starting k8s provider")

	config := kubernetes.Config{
		Resources: kubernetes.Resources{
			Pod:     kubernetes.Enabled{true},
			Node:    kubernetes.Enabled{true},
			Service: kubernetes.Enabled{true},
		},
	}
	config.InitDefaults()

	ctx := context.Background()

	provider := kubernetes.NewDynamicProvider(baseLogger, &config, false)
	providerState := composable.NewStateForProvider(ctx, provider)
	go func() {
		err := provider.Run(&providerState)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	for {
		select {
		case <-providerState.SignalChan():
			mappings = providerState.Mappings()
			baseLogger.Infow("got mappings", logp.Reflect("mappings", mappings))
		case <-ctx.Done():
			break
		}
	}
}

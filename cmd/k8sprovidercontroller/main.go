// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/composable"

	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/agent"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/docker"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/env"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/host"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetes"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetesleaderelection"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetessecrets"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/local"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/localdynamic"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/path"

	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var vars []*transpiler.Vars

func main() {
	defaultCfg := logger.DefaultLoggingConfig()
	defaultCfg.Level = logp.DebugLevel
	defaultCfg.ToStderr = true

	defaultEventLogCfg := logger.DefaultEventLoggingConfig()
	baseLogger, err := logger.NewFromConfig("", defaultCfg, defaultEventLogCfg, false)
	if err != nil {
		panic(err)
	}

	baseLogger.Info("Starting k8s provider")

	ctx := context.Background()

	rawConfig := config.New()
	if err != nil {
		panic(err)
	}
	controller, err := composable.New(baseLogger, rawConfig, false)
	if err != nil {
		panic(err)
	}

	go func() {
		err := controller.Run(ctx)
		if err != nil {
			panic(err)
		}
	}()
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	for {
		select {
		case vars = <-controller.Watch():
			maps := []map[string]any{}
			for _, v := range vars {
				vmap, err := v.Map()
				if err != nil {
					panic(err)
				}
				maps = append(maps, vmap)
			}
			baseLogger.Infow("got vars", logp.Reflect("vars", maps))
		case <-ctx.Done():
			break
		}
	}
}

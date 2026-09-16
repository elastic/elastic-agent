// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package include registers all the composable providers with the composable
// registry. It exists as a single place that explicitly wires up every
// provider, replacing the previous pattern of each provider package
// registering itself via a package-level func init().
package include

import (
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/agent"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/docker"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/env"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/filesource"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/host"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetes"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetesleaderelection"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetessecrets"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/local"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/localdynamic"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/path"
)

var once sync.Once

// Providers registers all known composable providers with composable.Providers.
// It is safe to call multiple times; registration happens exactly once.
func Providers() {
	once.Do(func() {
		composable.Providers.MustAddContextProvider("agent", agent.ContextProviderBuilder)
		composable.Providers.MustAddDynamicProvider("docker", docker.DynamicProviderBuilder)
		composable.Providers.MustAddContextProvider("env", env.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("filesource", filesource.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("host", host.ContextProviderBuilder)
		composable.Providers.MustAddDynamicProvider("kubernetes", kubernetes.DynamicProviderBuilder)
		composable.Providers.MustAddContextProvider("kubernetes_leaderelection", kubernetesleaderelection.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("kubernetes_secrets", kubernetessecrets.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("local", local.ContextProviderBuilder)
		composable.Providers.MustAddDynamicProvider("local_dynamic", localdynamic.DynamicProviderBuilder)
		composable.Providers.MustAddContextProvider("path", path.ContextProviderBuilder)
	})
}

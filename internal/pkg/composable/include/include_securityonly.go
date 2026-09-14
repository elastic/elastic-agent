// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build securityonly

// Package include registers all the composable providers with the composable
// registry. It exists as a single place that explicitly wires up every
// provider, replacing the previous pattern of each provider package
// registering itself via a package-level func init().
package include

import (
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/agent"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/env"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/filesource"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/host"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/local"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/localdynamic"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/path"
)

var once sync.Once

// Providers registers the composable providers available in the security-only variant.
// Docker and Kubernetes providers are excluded — the security-only variant does not
// run in container orchestration environments and their dependencies are unnecessary.
func Providers() {
	once.Do(func() {
		composable.Providers.MustAddContextProvider("agent", agent.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("env", env.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("filesource", filesource.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("host", host.ContextProviderBuilder)
		composable.Providers.MustAddContextProvider("local", local.ContextProviderBuilder)
		composable.Providers.MustAddDynamicProvider("local_dynamic", localdynamic.DynamicProviderBuilder)
		composable.Providers.MustAddContextProvider("path", path.ContextProviderBuilder)
	})
}

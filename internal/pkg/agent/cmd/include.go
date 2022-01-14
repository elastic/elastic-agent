// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	// include the composable providers
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/agent"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/docker"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/env"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/host"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/kubernetes"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/kubernetesleaderelection"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/kubernetessecrets"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/local"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/localdynamic"
	_ "github.com/elastic/elastic-agent-poc/internal/pkg/composable/providers/path"
)

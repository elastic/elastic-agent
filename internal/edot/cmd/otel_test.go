// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
<<<<<<< HEAD
	"os"
	"strings"
=======
>>>>>>> 6edfcdb (test: fix EDOT Collector tests (#17084))
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/edot/otelcol/agentprovider"
)

func TestPrepareCollectorSettings(t *testing.T) {
	t.Run("returns valid settings in supervised mode", func(t *testing.T) {
		settings, err := prepareCollectorSettings([]string{"stdingob:"}, true, "info", nil)
		require.NoError(t, err, "failed to prepare collector settings")
		require.NotNil(t, settings, "settings should not be nil")
<<<<<<< HEAD
		require.NotNil(t, settings.otelSettings.ConfigProviderSettings.ResolverSettings.URIs, "URIs should not be nil")
		agentProviderURIFound := false
		for _, uri := range settings.otelSettings.ConfigProviderSettings.ResolverSettings.URIs {
			agentProviderURIFound = strings.Contains(uri, agentprovider.AgentConfigProviderSchemeName)
			if agentProviderURIFound {
				break
			}
		}
		require.True(t, agentProviderURIFound, "agentprovider Scheme not found in the URIS of ConfigProviderSettings")
=======
		require.Contains(t, settings.otelSettings.ConfigProviderSettings.ResolverSettings.URIs, "stdingob:", "stdingob: not found in the URIs of ConfigProviderSettings")
>>>>>>> 6edfcdb (test: fix EDOT Collector tests (#17084))
		require.NotNil(t, settings.otelSettings.LoggingOptions, "loggingOptions should not be nil for supervised mode")
	})

	t.Run("returns valid settings in standalone mode", func(t *testing.T) {
		settings, err := prepareCollectorSettings([]string{"fake-config.yaml"}, false, "info", nil)
		require.NoError(t, err, "failed to prepare collector settings")
		require.NotNil(t, settings, "settings should not be nil")
		require.Contains(t, settings.otelSettings.ConfigProviderSettings.ResolverSettings.URIs, "fake-config.yaml", "fake-config.yaml not found in the URIS of ConfigProviderSettings")
	})
}

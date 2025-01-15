// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configprovider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestOTelConfigProvider(t *testing.T) {
	t.Run("file-provider", func(t *testing.T) {
		pf := NewFactory(fileprovider.NewFactory)
		prSet := confmap.ProviderSettings{}
		provider := pf.Create(prSet)
		ret, err := provider.Retrieve(context.Background(), "file:./test-otel-config.yml", nil)
		require.NoError(t, err)

		raw, err := ret.AsRaw()
		require.NoError(t, err)

		mapRaw, ok := raw.(map[string]interface{})
		require.True(t, ok)

		for _, key := range config.OTelConfKeys {
			_, ok := mapRaw[key]
			if ok {
				delete(mapRaw, key)
			}
		}
		require.Equal(t, 0, len(mapRaw))
	})
}

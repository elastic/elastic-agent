// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

func TestInjectOpAMPExtension(t *testing.T) {
	const (
		extensionID    = "opamp/test-uuid"
		instanceUID    = "01940000-0000-7000-8000-000000000000"
		serverEndpoint = "http://127.0.0.1:7654/v1/opamp"
		secret         = "shh"
	)

	t.Run("adds_extension_and_service_listing_into_empty_config", func(t *testing.T) {
		conf := confmap.New()
		require.NoError(t, injectOpAMPExtension(conf, extensionID, instanceUID, serverEndpoint, secret))

		require.True(t, conf.IsSet("extensions::"+extensionID))
		assert.Equal(t, instanceUID, conf.Get("extensions::"+extensionID+"::instance_uid"))
		assert.Equal(t, serverEndpoint, conf.Get("extensions::"+extensionID+"::server::http::endpoint"))
		assert.Equal(t, opampPollingInterval, conf.Get("extensions::"+extensionID+"::server::http::polling_interval"))
		assert.Equal(t,
			"Bearer "+secret,
			conf.Get("extensions::"+extensionID+"::server::http::headers::"+opampAuthorizationHeader),
		)

		assert.Equal(t, true, conf.Get("extensions::"+extensionID+"::capabilities::reports_health"))
		assert.Equal(t, false, conf.Get("extensions::"+extensionID+"::capabilities::reports_effective_config"))
		assert.Equal(t, false, conf.Get("extensions::"+extensionID+"::capabilities::reports_available_components"))

		exts, ok := conf.Get("service::extensions").([]any)
		require.True(t, ok)
		assert.Contains(t, exts, extensionID)
	})

	t.Run("preserves_existing_service_extensions", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"extensions": []any{"existing/foo"},
			},
		})
		require.NoError(t, injectOpAMPExtension(conf, extensionID, instanceUID, serverEndpoint, secret))

		exts, ok := conf.Get("service::extensions").([]any)
		require.True(t, ok)
		assert.Contains(t, exts, "existing/foo")
		assert.Contains(t, exts, extensionID)
	})
}

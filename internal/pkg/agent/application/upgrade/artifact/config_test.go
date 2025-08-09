// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentlibsconfig "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
)

// TestConfigWithoutHTTPTransportSettings ensures configWithoutHTTPTransportSettings
// and Config stay aligned.
func TestConfigWithoutHTTPTransportSettings(t *testing.T) {
	cfg := reflect.TypeOf(Config{})
	cfgWithout := reflect.TypeOf(configWithoutHTTPTransportSettings{})
	transportSettings := reflect.TypeOf(httpcommon.HTTPTransportSettings{})

	var missing []string

	// get all the fields of httpcommon.HTTPTransportSettings
	// check configWithoutHTTPTransportSettings has all the fields of Config, but
	// the ones from httpcommon.HTTPTransportSettings

	// get all the fields of httpcommon.HTTPTransportSettings
	transportSettingsFields := []string{transportSettings.Name()}
	for i := 0; i < transportSettings.NumField(); i++ {
		transportSettingsFields = append(
			transportSettingsFields,
			transportSettings.Field(i).Name)
	}

	// check configWithoutHTTPTransportSettings has got all the fields Config
	// has, except the fields of httpcommon.HTTPTransportSettings.
	for i := 0; i < cfg.NumField(); i++ {
		field := cfg.Field(i).Name
		if slices.Contains(transportSettingsFields, field) {
			// configWithoutHTTPTransportSettings should not have this field
			continue
		}

		_, has := cfgWithout.FieldByName(field)
		if !has {
			missing = append(missing, field)
		}
	}

	if len(missing) != 0 {
		t.Errorf("type %s should have the same fields as Config, "+
			"except the httpcommon.HTTPTransportSettings fields. However it's "+
			"missing the fields %v",
			cfgWithout.Name(), missing)
	}
}

// TestConfig_Unpack takes a shortcut as testing every possible config would be
// hard to maintain, a new config would be added to Config and the test would not
// be updated. Instead, this test ensures the default config is preserved if an
// empty config is unpacked into it.
func TestConfig_Unpack(t *testing.T) {
	defaultcfg := DefaultConfig()

	emptycgf, err := agentlibsconfig.NewConfigFrom("")
	require.NoError(t, err, "could not create config from empty string")

	err = defaultcfg.Unpack(emptycgf)
	require.NoError(t, err, "UnpackTo failed")
	assert.Equal(t, DefaultConfig(), defaultcfg)
}

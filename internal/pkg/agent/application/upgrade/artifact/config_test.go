// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentlibsconfig "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestReload(t *testing.T) {
	type testCase struct {
		input                    string
		initialConfig            *Config
		expectedSourceURI        string
		expectedTargetDirectory  string
		expectedInstallDirectory string
		expectedDropDirectory    string
		expectedFingerprint      string
		expectedTLS              bool
		expectedTLSEnabled       bool
		expectedDisableProxy     bool
		expectedTimeout          time.Duration
	}
	defaultValues := DefaultConfig()
	testCases := []testCase{
		{
			input: `agent.download:
  sourceURI: "testing.uri"
  target_directory: "a/b/c"
  install_path: "i/p"
  drop_path: "d/p"
  proxy_disable: true
  timeout: 33s
  ssl.enabled: true
  ssl.ca_trusted_fingerprint: "my_finger_print"
`,
			initialConfig:            DefaultConfig(),
			expectedSourceURI:        "testing.uri",
			expectedTargetDirectory:  "a/b/c",
			expectedInstallDirectory: "i/p",
			expectedDropDirectory:    "d/p",
			expectedFingerprint:      "my_finger_print",
			expectedTLS:              true,
			expectedTLSEnabled:       true,
			expectedDisableProxy:     true,
			expectedTimeout:          33 * time.Second,
		},
		{
			input: `agent.download:
  sourceURI: "testing.uri"
`,
			initialConfig:            DefaultConfig(),
			expectedSourceURI:        "testing.uri",
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  sourceURI: ""
`,
			initialConfig: &Config{
				SourceURI:             "testing.uri",
				HTTPTransportSettings: defaultValues.HTTPTransportSettings,
			},
			expectedSourceURI:        defaultValues.SourceURI, // fallback to default when set to empty
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: ``,
			initialConfig: &Config{
				SourceURI:             "testing.uri",
				HTTPTransportSettings: defaultValues.HTTPTransportSettings,
			},
			expectedSourceURI:        defaultValues.SourceURI, // fallback to default when not set
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  sourceURI: " "
`,
			initialConfig: &Config{
				SourceURI:             "testing.uri",
				HTTPTransportSettings: defaultValues.HTTPTransportSettings,
			},
			expectedSourceURI:        defaultValues.SourceURI, // fallback to default when set to whitespace
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  source_uri: " "
`,
			initialConfig: &Config{
				SourceURI:             "testing.uri",
				HTTPTransportSettings: defaultValues.HTTPTransportSettings,
			},
			expectedSourceURI:        defaultValues.SourceURI, // fallback to default when set to whitespace
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  source_uri: " "
  sourceURI: " "
`,
			initialConfig:            DefaultConfig(),
			expectedSourceURI:        defaultValues.SourceURI, // fallback to default when set to whitespace
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: ``,
			initialConfig: &Config{
				SourceURI:             "testing.uri",
				HTTPTransportSettings: defaultValues.HTTPTransportSettings,
			},
			expectedSourceURI:        defaultValues.SourceURI,
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  source_uri: " "
  sourceURI: "testing.uri"
`,
			initialConfig:            DefaultConfig(),
			expectedSourceURI:        "testing.uri",
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  source_uri: "testing.uri"
  sourceURI: " "
`,
			initialConfig:            DefaultConfig(),
			expectedSourceURI:        "testing.uri",
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
		{
			input: `agent.download:
  source_uri: "testing.uri"
  sourceURI: "another.uri"
`,
			initialConfig:            DefaultConfig(),
			expectedSourceURI:        "testing.uri",
			expectedTargetDirectory:  defaultValues.TargetDirectory,
			expectedInstallDirectory: defaultValues.InstallPath,
			expectedDropDirectory:    defaultValues.DropPath,
			expectedFingerprint:      "",
			expectedTLS:              defaultValues.TLS != nil,
			expectedTLSEnabled:       false,
			expectedDisableProxy:     defaultValues.Proxy.Disable,
			expectedTimeout:          defaultValues.Timeout,
		},
	}

	l, _ := loggertest.New("t")
	for _, tc := range testCases {
		cfg := tc.initialConfig
		reloader := NewReloader(cfg, l)

		c, err := config.NewConfigFrom(tc.input)
		require.NoError(t, err)

		require.NoError(t, reloader.Reload(c))

		require.Equal(t, tc.expectedSourceURI, cfg.SourceURI)
		require.Equal(t, tc.expectedTargetDirectory, cfg.TargetDirectory)
		require.Equal(t, tc.expectedInstallDirectory, cfg.InstallPath)
		require.Equal(t, tc.expectedDropDirectory, cfg.DropPath)
		require.Equal(t, tc.expectedTimeout, cfg.Timeout)

		require.Equal(t, tc.expectedDisableProxy, cfg.Proxy.Disable)

		if tc.expectedTLS {
			require.NotNil(t, cfg.TLS)
			require.Equal(t, tc.expectedTLSEnabled, *cfg.TLS.Enabled)
			require.Equal(t, tc.expectedFingerprint, cfg.TLS.CATrustedFingerprint)
		} else {
			require.Nil(t, cfg.TLS)
		}
	}
}

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

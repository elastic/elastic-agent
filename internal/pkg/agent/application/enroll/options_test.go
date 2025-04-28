// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"encoding/json"
	"testing"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/stretchr/testify/require"
)

func TestRemoteConfig(t *testing.T) {
	cases := []struct {
		name                   string
		failOnInsecureMismatch bool
		options                EnrollOptions

		expectedRemote remote.Config
		expectedError  bool
	}{
		{
			"invalid URI",
			false,
			EnrollOptions{URL: "http:?/1213!@#$%^"},
			remote.Config{},
			true,
		},
		{
			"insecure",
			true,
			EnrollOptions{URL: "http://localhost", Insecure: false},
			remote.Config{},
			true,
		},
		{
			"insecure - no fail",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS:     &tlscommon.Config{},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"CAs persisted",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false, CAs: []string{"ca"}},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						CAs: []string{"ca"},
					},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"CA SHA persisted",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false, CASha256: []string{"ca_sha"}},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						CASha256: []string{"ca_sha"},
					},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"CA and SHA persisted",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false, CAs: []string{"ca"}, CASha256: []string{"ca_sha"}},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						CAs:      []string{"ca"},
						CASha256: []string{"ca_sha"},
					},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"Cert persisted",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false, Certificate: "cert"},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						Certificate: tlscommon.CertificateConfig{
							Certificate: "cert",
						},
					},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"Cert key persisted",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false, Key: "cert_key"},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						Certificate: tlscommon.CertificateConfig{
							Key: "cert_key",
						},
					},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"Cert and key persisted",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false, Certificate: "cert", Key: "cert_key"},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						Certificate: tlscommon.CertificateConfig{
							Certificate: "cert",
							Key:         "cert_key",
						},
					},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
				},
			},
			false,
		},
		{
			"Proxy settings",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false,
				ProxyURL: "proxy.url", ProxyHeaders: map[string]string{"header": "value"}, ProxyDisabled: false,
			},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS:     &tlscommon.Config{},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
					Proxy: httpcommon.HTTPClientProxySettings{
						URL:     &httpcommon.ProxyURI{Scheme: "", Path: "proxy.url"},
						Headers: map[string]string{"header": "value"},
						Disable: false,
					},
				},
			},
			false,
		},

		{
			"Proxy settings - disabled when fleet server specified",
			false,
			EnrollOptions{URL: "http://localhost", Insecure: false,
				ProxyURL: "proxy.url", ProxyHeaders: map[string]string{"header": "value"}, ProxyDisabled: false,
				FleetServer: EnrollCmdFleetServerOption{ConnStr: "fleet.server/connection/string"},
			},
			remote.Config{
				Protocol: "http",
				SpaceID:  "",
				Path:     "",
				Host:     "localhost",
				Transport: httpcommon.HTTPTransportSettings{
					TLS:     &tlscommon.Config{},
					Timeout: remote.DefaultClientConfig().Transport.Timeout,
					Proxy: httpcommon.HTTPClientProxySettings{
						URL:     &httpcommon.ProxyURI{Scheme: "", Path: "proxy.url"},
						Headers: map[string]string{"header": "value"},
						Disable: true,
					},
				},
			},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actCfg, actErr := tc.options.RemoteConfig(tc.failOnInsecureMismatch)
			if tc.expectedError {
				require.Error(t, actErr)
				return
			}

			require.NoError(t, actErr)
			require.EqualValues(t, tc.expectedRemote, actCfg)
		})
	}
}

func TestMergeOptionsWithMigrateAction(t *testing.T) {
	cases := []struct {
		name    string
		action  *fleetapi.ActionMigrate
		options EnrollOptions

		expectedOptions EnrollOptions
		expectedError   bool
	}{
		{
			"required: Enrollment Token",
			&fleetapi.ActionMigrate{
				Data: fleetapi.ActionMigrateData{
					EnrollmentToken: "",
					TargetURI:       "uri",
				},
			},
			EnrollOptions{},
			EnrollOptions{},
			true,
		},
		{
			"required: Target URI",
			&fleetapi.ActionMigrate{
				Data: fleetapi.ActionMigrateData{
					EnrollmentToken: "token",
					TargetURI:       "",
				},
			},
			EnrollOptions{},
			EnrollOptions{},
			true,
		},
		{
			"basic options",
			&fleetapi.ActionMigrate{
				Data: fleetapi.ActionMigrateData{
					EnrollmentToken: "token",
					TargetURI:       "uri",
				},
			},
			EnrollOptions{},
			EnrollOptions{
				EnrollAPIKey: "token",
				URL:          "uri",
			},
			false,
		},
		{
			"overwrite fields",
			&fleetapi.ActionMigrate{
				Data: fleetapi.ActionMigrateData{
					EnrollmentToken: "token",
					TargetURI:       "uri",
					Settings:        json.RawMessage(`{"insecure": true, "replace_token": "replace-token", "tags":["a","b"]}`),
				},
			},
			EnrollOptions{
				ReplaceToken: "value",
			},
			EnrollOptions{
				EnrollAPIKey: "token",
				URL:          "uri",
				ReplaceToken: "replace-token",
				Insecure:     true,
				Tags:         []string{"a", "b"},
			},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actOptions, actErr := MergeOptionsWithMigrateAction(tc.action, tc.options)
			if tc.expectedError {
				require.Error(t, actErr)
				return
			}

			require.NoError(t, actErr)
			require.EqualValues(t, tc.expectedOptions, actOptions)
		})
	}
}

func TestFromFleetConfig(t *testing.T) {
	defaultFleetAgentCfg := configuration.DefaultFleetAgentConfig()
	cases := []struct {
		name   string
		config *configuration.FleetAgentConfig

		expectedOptions EnrollOptions
	}{
		{
			"basic scenario",
			&configuration.FleetAgentConfig{},
			EnrollOptions{},
		},
		{
			"default config",
			defaultFleetAgentCfg,
			EnrollOptions{
				URL:          defaultFleetAgentCfg.Client.Host,
				EnrollAPIKey: defaultFleetAgentCfg.AccessAPIKey,
				ProxyHeaders: make(map[string]string),
			},
		},
		{
			"full config",
			&configuration.FleetAgentConfig{
				AccessAPIKey: "api-key",
				Client: remote.Config{
					Protocol: "httpx", //should be ignored
					Path:     "path",  // should be ignored
					Host:     "https://localhost.ignored",
					Hosts:    []string{"https://localhost"},
					Transport: httpcommon.HTTPTransportSettings{
						Proxy: httpcommon.HTTPClientProxySettings{
							URL:     &httpcommon.ProxyURI{Path: "proxy.url"},
							Disable: true,
							Headers: map[string]string{
								"header": "value",
							},
						},
						TLS: &tlscommon.Config{
							CAs:      []string{"ca1"},
							CASha256: []string{"ca1_sha"},
							Certificate: tlscommon.CertificateConfig{
								Certificate:    "cert",
								Key:            "key",
								PassphrasePath: "pass/path",
							},
							VerificationMode: tlscommon.VerifyNone, // insecure
						},
					},
				},
				Info: &configuration.AgentInfo{
					ID: "agent-id",
				},
			},
			EnrollOptions{
				URL:               "https://localhost",
				CAs:               []string{"ca1"},
				CASha256:          []string{"ca1_sha"},
				Certificate:       "cert",
				Key:               "key",
				KeyPassphrasePath: "pass/path",
				Insecure:          true,
				ID:                "agent-id",

				EnrollAPIKey: "api-key",

				ProxyURL:      "proxy.url",
				ProxyDisabled: true,
				ProxyHeaders:  map[string]string{"header": "value"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actOptions := FromFleetConfig(tc.config)
			require.EqualValues(t, tc.expectedOptions, actOptions)
		})
	}
}

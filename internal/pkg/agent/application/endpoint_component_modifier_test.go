// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/elastic/elastic-agent/pkg/component"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestEndpointComponentModifier(t *testing.T) {
	log, obs := loggertest.New("TestEndpointSignedComponentModifier")
	defer func() {
		if !t.Failed() {
			return
		}

		loggertest.PrintObservedLogs(obs.TakeAll(), t.Log)
	}()

	pair, certPath, certKeyPath, certKeyPassPath := prepareEncTLSCertificates(t)

	tests := map[string][]struct {
		name         string
		compModifier coordinator.ComponentsModifier
		comps        []component.Component
		cfg          map[string]interface{}
		wantComps    []component.Component
		wantErr      func(*testing.T, error)
	}{
		"EndpointSignedComponentModifier": {
			{
				name:         "nil",
				compModifier: EndpointSignedComponentModifier(),
			},
			{
				name:         "non endpoint",
				compModifier: EndpointSignedComponentModifier(),
				comps: []component.Component{
					{
						ID: "asdfasd",
						InputSpec: &component.InputRuntimeSpec{
							InputType: "osquery",
						},
						Units: []component.Unit{
							{
								ID:   "34534",
								Type: client.UnitTypeInput,
							},
						},
					},
				},
				wantComps: []component.Component{
					{
						ID: "asdfasd",
						InputSpec: &component.InputRuntimeSpec{
							InputType: "osquery",
						},
						Units: []component.Unit{
							{
								ID:   "34534",
								Type: client.UnitTypeInput,
							},
						},
					},
				},
			},
			{
				name:         "endpoint",
				compModifier: EndpointSignedComponentModifier(),
				comps: []component.Component{
					{
						ID: "asdfasd",
						InputSpec: &component.InputRuntimeSpec{
							InputType: "endpoint",
						},
						Units: []component.Unit{
							{
								ID:   "34534",
								Type: client.UnitTypeInput,
								Config: &proto.UnitExpectedConfig{
									Type:   "endpoint",
									Source: &structpb.Struct{},
								},
							},
						},
					},
				},
				cfg: map[string]interface{}{
					"signed": map[string]interface{}{
						"data":      "eyJpZCI6ImFhZWM4OTYwLWJiYjAtMTFlZC1hYzBkLTVmNjI0YTQxZjM4OCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRW1tckhDSTdtZ2tuZUJlYVJkc2VkQXZBU2l0UHRLbnpPdUlzeHZJRWdGTkFLVlg3MWpRTTVmalo1eUdsSDB0TmJuR2JrU2pVM0VEVUZsOWllQ1J0ME5nPT0ifX19",
						"signature": "MEUCIQCWoScyJW0dejHFxXBTEcSCOZiBHRVMjuJRPwFCwOdA1QIgKrtKUBzkvVeljRtJyMXfD8zIvWjrMzqhSkgjNESPW5E=",
					},
				},
				wantComps: []component.Component{
					{
						ID: "asdfasd",
						InputSpec: &component.InputRuntimeSpec{
							InputType: "endpoint",
						},
						Units: []component.Unit{
							{
								ID:   "34534",
								Type: client.UnitTypeInput,
								Config: &proto.UnitExpectedConfig{
									Source: func() *structpb.Struct {
										var source structpb.Struct
										err := source.UnmarshalJSON([]byte(`{"signed":{"data":"eyJpZCI6ImFhZWM4OTYwLWJiYjAtMTFlZC1hYzBkLTVmNjI0YTQxZjM4OCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRW1tckhDSTdtZ2tuZUJlYVJkc2VkQXZBU2l0UHRLbnpPdUlzeHZJRWdGTkFLVlg3MWpRTTVmalo1eUdsSDB0TmJuR2JrU2pVM0VEVUZsOWllQ1J0ME5nPT0ifX19", "signature":"MEUCIQCWoScyJW0dejHFxXBTEcSCOZiBHRVMjuJRPwFCwOdA1QIgKrtKUBzkvVeljRtJyMXfD8zIvWjrMzqhSkgjNESPW5E="}}`))
										require.NoError(t, err, "could not create want component source config")
										return &source
									}(),
								},
							},
						},
					},
				},
			},
		},
		"EndpointTLSComponentModifier": {
			{
				name:         "nil",
				compModifier: EndpointSignedComponentModifier(),
			},
			{
				name:         "non endpoint",
				compModifier: EndpointSignedComponentModifier(),
				comps:        makeComponent(t, "{}"),
				wantComps:    makeComponent(t, "{}"),
			},

			{
				name:         "endpoint-no-fleet",
				compModifier: EndpointTLSComponentModifier(log),
				comps:        makeComponent(t, `{}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{},
				},
				wantComps: makeComponent(t, `{}`),
			},
			{
				name:         "endpoint-no-fleet-wrong-type",
				compModifier: EndpointTLSComponentModifier(log),
				comps:        makeComponent(t, `{"fleet": 42}`),
				cfg: map[string]interface{}{
					"fleet": 1,
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'fleet' node isn't a map")
				},
			},
			{
				name:         "endpoint-no-fleet.ssl",
				compModifier: EndpointTLSComponentModifier(log),
				comps:        makeComponent(t, `{"fleet": {}}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{},
				},
				wantComps: makeComponent(t, `{"fleet": {}}`),
			},
			{
				name:         "endpoint-wrong-fleet.ssl",
				compModifier: EndpointTLSComponentModifier(log),
				comps:        makeComponent(t, `{"fleet": {"ssl": 42}}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{},
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'ssl' node isn't a map")
				},
			},
			{
				name:         "endpoint-wrong-fleet.ssl.key_passphrase_path",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `
			{"fleet": {"ssl":
			  {"key_passphrase_path": 42}}}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{},
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'key_passphrase_path' isn't a string")
				},
			},
			{
				name:         "endpoint-wrong-fleet.ssl.key",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `
{"fleet": {"ssl": {
  "key_passphrase_path": "/path/to/passphrase",
  "key": 42}}}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{},
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'key' isn't a string")
				},
			},
			{
				name:         "endpoint-wrong-fleet.ssl.certificate",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `
			{"fleet": {"ssl": {
			  "key_passphrase_path": "/path/to/passphrase",
			  "key": "",
			  "certificate": 42}}}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{},
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'certificate' isn't a string")
				},
			},

			{
				name:         "endpoint-mTLS-passphrase",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q,
			      "key_passphrase_path": %q
			    }
			  }
			}`, certPath, certKeyPath, certKeyPassPath)),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{
						"ssl": map[string]interface{}{
							"certificate":         certPath,
							"key":                 certKeyPath,
							"key_passphrase_path": certKeyPassPath,
						},
					},
				},
				wantComps: makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q
			    }
			  }
			}`, pair.Cert, pair.Key)),
			},
			{
				name:         "endpoint-mTLS-passphrase-no-key",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key_passphrase_path": %q
			    }
			  }
			}`, certPath, certKeyPassPath)),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{
						"ssl": map[string]interface{}{
							"certificate":         certPath,
							"key_passphrase_path": certKeyPassPath,
						},
					},
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'key' isn't present")
				},
			},
			{
				name:         "endpoint-mTLS-passphrase-no-certificate",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
			      "key": "/path/to/key",
			      "key_passphrase_path": "/path/to/key_passphrase_path"
			    }
			  }
			}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{
						"ssl": map[string]interface{}{
							"key":                 "/path/to/cert",
							"key_passphrase_path": "/path/to/key_passphrase_path",
						},
					},
				},
				wantComps: nil,
				wantErr: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "'certificate' isn't present")
				},
			},
			{
				name:         "endpoint-mTLS-no-passphrase",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
			      "certificate": "/path/to/cert",
			      "key": "/path/to/key"
			    }
			  }
			}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{
						"ssl": map[string]interface{}{
							"certificate": "/path/to/cert",
							"key":         "/path/to/key",
						},
					},
				},
				wantComps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
			      "certificate": "/path/to/cert",
			      "key": "/path/to/key"
			    }
			  }
			}`),
			},
			{
				name:         "endpoint-mTLS-empty-passphrase",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
                  "key_passphrase_path": "",
			      "certificate": "/path/to/cert",
			      "key": "/path/to/key"
			    }
			  }
			}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{
						"ssl": map[string]interface{}{
							"key_passphrase_path": "",
							"certificate":         "/path/to/cert",
							"key":                 "/path/to/key",
						},
					},
				},
				wantComps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
                  "key_passphrase_path": "",
			      "certificate": "/path/to/cert",
			      "key": "/path/to/key"
			    }
			  }
			}`),
			},
			{
				name:         "endpoint-TLS",
				compModifier: EndpointTLSComponentModifier(log),
				comps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
			      "certificate_authorities": ["/path/to/ca1", "/path/to/ca2"]
			    }
			  }
			}`),
				cfg: map[string]interface{}{
					"fleet": map[string]interface{}{
						"ssl": map[string]interface{}{
							"certificate_authorities": []string{"/path/to/ca1", "/path/to/ca2"},
						},
					},
				},
				wantComps: makeComponent(t, `{
			  "fleet": {
			    "ssl": {
			      "certificate_authorities": ["/path/to/ca1", "/path/to/ca2"]
			    }
			  }
			}`),
			},
		},
	}

	for name, tcs := range tests {
		t.Run(name, func(t *testing.T) {
			for _, tc := range tcs {
				t.Run(tc.name, func(t *testing.T) {
					comps, err := tc.compModifier(tc.comps, tc.cfg)

					if tc.wantErr != nil {
						tc.wantErr(t, err)
					} else {
						assert.NoError(t, err)
					}

					// Cumbersome comparison of the source config encoded in protobuf,
					// cmp panics protobufs comparison otherwise.
					compareComponents(t, comps, tc.wantComps)
				})
			}
		})
	}
}

func compareComponents(t *testing.T, got, want []component.Component) {
	if len(want) > 0 &&
		len(want[0].Units) > 0 &&
		got[0].Units[0].Config != nil &&
		got[0].Units[0].Config.Source != nil {

		unitCgf := got[0].Units[0].Config.Source.AsMap()
		wantUnitCfg := want[0].Units[0].Config.Source.AsMap()

		assert.Equal(t, wantUnitCfg, unitCgf, "unit config do not match")
	}
}

func TestEndpointTLSComponentModifier_cache_miss(t *testing.T) {
	log, obs := loggertest.New("TestEndpointSignedComponentModifier")
	defer func() {
		if !t.Failed() {
			return
		}

		loggertest.PrintObservedLogs(obs.TakeAll(), t.Log)
	}()

	pair, certPath, certKeyPath, certKeyPassPath := prepareEncTLSCertificates(t)

	comps := makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q,
			      "key_passphrase_path": %q
			    }
			  }
			}`, certPath, certKeyPath, certKeyPassPath))
	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"ssl": map[string]interface{}{
				"certificate":         certPath,
				"key":                 certKeyPath,
				"key_passphrase_path": certKeyPassPath,
			},
		},
	}
	wantComps := makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q
			    }
			  }
			}`, pair.Cert, pair.Key))

	cache := tlsCache{mu: &sync.Mutex{}}
	modifier := newEndpointTLSComponentModifier(log, &cache)
	got, err := modifier(comps, cfg)
	require.NoError(t, err, "unexpected error")

	assert.Equal(t, certKeyPassPath, cache.PassphrasePath, "passphrase path did not match")
	assert.Equal(t, string(pair.Cert), cache.Certificate, "certificate did not match")
	assert.Equal(t, string(pair.Key), cache.Key, "key did not match")

	compareComponents(t, got, wantComps)
}

func TestEndpointTLSComponentModifier_cache_hit(t *testing.T) {
	log, obs := loggertest.New("TestEndpointSignedComponentModifier")
	defer func() {
		if !t.Failed() {
			return
		}

		loggertest.PrintObservedLogs(obs.TakeAll(), t.Log)
	}()

	certPath := "/path/to/cert"
	certKeyPath := "/path/to/key"
	certKeyPassPath := "/path/to/key_passphrase_path"
	cache := tlsCache{
		mu: &sync.Mutex{},

		PassphrasePath: certKeyPassPath,
		Certificate:    "cached certificate",
		Key:            "cached key",
	}

	comps := makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q,
			      "key_passphrase_path": %q
			    }
			  }
			}`, certPath, certKeyPath, certKeyPassPath))
	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"ssl": map[string]interface{}{
				"certificate":         cache.Certificate,
				"key":                 cache.Key,
				"key_passphrase_path": cache.PassphrasePath,
			},
		},
	}

	wantComps := makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q
			    }
			  }
			}`, cache.Certificate, cache.Key))

	modifier := newEndpointTLSComponentModifier(log, &cache)
	got, err := modifier(comps, cfg)
	require.NoError(t, err, "unexpected error")

	assert.Equal(t, certKeyPassPath, cache.PassphrasePath, "passphrase should not have changed")
	compareComponents(t, got, wantComps)
}

func prepareEncTLSCertificates(t *testing.T) (certutil.Pair, string, string, string) {
	passphrase := "secure_passphrase"
	_, _, pair, err := certutil.NewRootCA()
	require.NoError(t, err, "could not create TLS certificate")
	agentChildDERKey, _ := pem.Decode(pair.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	encPem, err := x509.EncryptPEMBlock( //nolint:staticcheck // we need to drop support for this, but while we don't, it needs to be tested.
		rand.Reader,
		"EC PRIVATE KEY",
		agentChildDERKey.Bytes,
		[]byte(passphrase),
		x509.PEMCipherAES128)
	require.NoError(t, err, "failed encrypting agent child certificate key block")

	certKeyEnc := pem.EncodeToMemory(encPem)

	// save to disk
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	certKeyPath := filepath.Join(tmpDir, "key.pem")
	certKeyPassPath := filepath.Join(tmpDir, "key_pass.pem")

	err = os.WriteFile(certPath, pair.Cert, 0400)
	require.NoError(t, err, "could write certificate key")
	err = os.WriteFile(certKeyPath, certKeyEnc, 0400)
	require.NoError(t, err, "could write certificate key")
	err = os.WriteFile(certKeyPassPath, []byte(passphrase), 0400)
	require.NoError(t, err, "could write certificate key passphrase")

	return pair, certPath, certKeyPath, certKeyPassPath
}

func makeComponent(t *testing.T, sourceCfg string) []component.Component {
	return []component.Component{
		{
			ID: "ClientCertKey",
			InputSpec: &component.InputRuntimeSpec{
				InputType: "endpoint",
			},
			Units: []component.Unit{
				{
					ID:   "34534",
					Type: client.UnitTypeInput,
					Config: &proto.UnitExpectedConfig{
						Type: "endpoint",
						Source: func() *structpb.Struct {
							var source structpb.Struct
							err := source.UnmarshalJSON([]byte(sourceCfg))
							require.NoError(t, err, "could not create component source config")
							return &source
						}(),
					},
				},
			},
		},
	}
}

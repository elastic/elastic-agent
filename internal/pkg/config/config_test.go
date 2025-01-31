// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"

	"github.com/elastic/go-ucfg"
)

func TestConfig(t *testing.T) {
	testToMapStr(t)
	testLoadFiles(t)
}

func TestInputsResolveNOOP(t *testing.T) {
	contents := map[string]interface{}{
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type":     "elasticsearch",
				"hosts":    []interface{}{"127.0.0.1:9200"},
				"username": "${env.ES_USER}",
				"password": "${env.ES_PASSWORD}",
			},
		},
		"inputs": []interface{}{
			map[string]interface{}{
				"type": "logfile",
				"streams": []interface{}{
					map[string]interface{}{
						"paths": []interface{}{"/var/log/${host.name}"},
					},
				},
			},
		},
	}

	tmp := t.TempDir()

	cfgPath := filepath.Join(tmp, "config.yml")
	dumpToYAML(t, cfgPath, contents)

	cfg, err := LoadFile(cfgPath)
	require.NoError(t, err)

	cfgData, err := cfg.ToMapStr()
	require.NoError(t, err)
	require.Equal(t, contents, cfgData)

	// run `ToMapStr` again to ensure that the result is the
	// same, this is because the `cfg` has to be mutated for
	// `ToMapStr` to with the `SkipVars()` option
	cfgData, err = cfg.ToMapStr()
	require.NoError(t, err)
	assert.Equal(t, contents, cfgData)
}

func testToMapStr(t *testing.T) {
	m := map[string]interface{}{
		"hello": map[string]interface{}{
			"what": "who",
		},
	}

	c := MustNewConfigFrom(m)
	nm, err := c.ToMapStr()
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(m, nm))
}

func TestCommaParsing(t *testing.T) {
	t.Setenv("testname", "motmot")
	// test to make sure that we don't blow up the parsers when we have a `,` in a string
	inMap := map[string]interface{}{
		"test": "startsWith('${testname}','motmot')",
	}
	outMap := map[string]interface{}{
		"test": "startsWith('motmot','motmot')",
	}
	c := MustNewConfigFrom(inMap)
	parsedMap, err := c.ToMapStr()
	require.NoError(t, err)
	t.Logf("got :%#v", parsedMap)
	require.Equal(t, outMap, parsedMap)
}

func testLoadFiles(t *testing.T) {
	tmp := t.TempDir()

	f1 := filepath.Join(tmp, "1.yml")
	dumpToYAML(t, f1, map[string]interface{}{
		"hello": map[string]interface{}{
			"what": "1",
		},
	})

	f2 := filepath.Join(tmp, "2.yml")
	dumpToYAML(t, f2, map[string]interface{}{
		"hello": map[string]interface{}{
			"where": "2",
		},
	})

	f3 := filepath.Join(tmp, "3.yml")
	dumpToYAML(t, f3, map[string]interface{}{
		"super": map[string]interface{}{
			"awesome": "cool",
		},
	})

	c, err := LoadFiles(f1, f2, f3)
	require.NoError(t, err)

	r, err := c.ToMapStr()
	require.NoError(t, err)

	assert.Equal(t, map[string]interface{}{
		"hello": map[string]interface{}{
			"what":  "1",
			"where": "2",
		},
		"super": map[string]interface{}{
			"awesome": "cool",
		},
	}, r)
}

func dumpToYAML(t *testing.T, out string, in interface{}) {
	b, err := yaml.Marshal(in)
	require.NoError(t, err)
	err = os.WriteFile(out, b, 0600)
	require.NoError(t, err)
}

func TestDollarSignsInInputs(t *testing.T) {
	in := map[string]interface{}{
		"inputs": []interface{}{
			map[string]interface{}{
				"type": "logfile",
				"what": "$$$$",
			},
		},
	}
	c := MustNewConfigFrom(in)
	out, err := c.ToMapStr()
	assert.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestConfigUnpack(t *testing.T) {
	c := &struct {
		// go-ucfg will call the Unpacker interface
		Inner *Config
	}{}
	in := map[string]interface{}{
		"inner": map[string]interface{}{
			"key": "value",
		},
	}
	cfg := MustNewConfigFrom(in)
	require.NoError(t, cfg.UnpackTo(c))

	require.NotNil(t, c.Inner.Agent)
	val, err := c.Inner.Agent.String("key", 0)
	require.NoError(t, err)
	assert.Equal(t, "value", val)
}

func TestConfigOTelNNil(t *testing.T) {
	c, err := NewConfigFrom(map[string]interface{}{
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type":     "elasticsearch",
				"hosts":    []interface{}{"127.0.0.1:9200"},
				"username": "elastic",
				"password": "changeme",
			},
		},
		"inputs": []interface{}{
			map[string]interface{}{
				"type": "logfile",
				"streams": []interface{}{
					map[string]interface{}{
						"paths": []interface{}{"/var/log/syslog"},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, c.Agent)
	assert.Nil(t, c.OTel)
}

func TestConfigOTelNotNil(t *testing.T) {
	c, err := NewConfigFrom(map[string]interface{}{
		"outputs": map[string]interface{}{
			"default": map[string]interface{}{
				"type":     "elasticsearch",
				"hosts":    []interface{}{"127.0.0.1:9200"},
				"username": "elastic",
				"password": "changeme",
			},
		},
		"inputs": []interface{}{
			map[string]interface{}{
				"type": "logfile",
				"streams": []interface{}{
					map[string]interface{}{
						"paths": []interface{}{"/var/log/syslog"},
					},
				},
			},
		},
		"connectors": map[string]interface{}{
			"count": map[string]interface{}{},
		},
		"receivers": map[string]interface{}{
			"otlp": map[string]interface{}{
				"protocols": map[string]interface{}{
					"grpc": map[string]interface{}{
						"endpoint": "0.0.0.0:4317",
					},
				},
			},
		},
		"processors": map[string]interface{}{
			"batch": map[string]interface{}{},
		},
		"exporters": map[string]interface{}{
			"otlp": map[string]interface{}{
				"endpoint": "otelcol:4317",
			},
		},
		"extensions": map[string]interface{}{
			"health_check": map[string]interface{}{},
			"pprof":        map[string]interface{}{},
		},
		"service": map[string]interface{}{
			"extensions": []string{"health_check", "pprof"},
			"pipelines": map[string]interface{}{
				"traces": map[string]interface{}{
					"receivers":  []string{"otlp"},
					"processors": []string{"batch"},
					"exporters":  []string{"otlp"},
				},
				"metrics": map[string]interface{}{
					"receivers":  []string{"otlp"},
					"processors": []string{"batch"},
					"exporters":  []string{"otlp"},
				},
				"logs": map[string]interface{}{
					"receivers":  []string{"otlp"},
					"processors": []string{"batch"},
					"exporters":  []string{"otlp"},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, c.Agent)

	require.NotNil(t, c.OTel)
	assert.NotNil(t, c.OTel.Get("connectors"))
	assert.NotNil(t, c.OTel.Get("receivers"))
	assert.NotNil(t, c.OTel.Get("processors"))
	assert.NotNil(t, c.OTel.Get("exporters"))
	assert.NotNil(t, c.OTel.Get("extensions"))
	assert.NotNil(t, c.OTel.Get("service"))
}

func TestConfigMerge(t *testing.T) {
	scenarios := []struct {
		Name   string
		Into   *Config
		From   *Config
		Result *Config
	}{
		{
			Name: "no otel",
			Into: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"a": "value-a",
				},
			}), nil),
			From: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"b": "value-b",
				},
			}), nil),
			Result: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"a": "value-a",
					"b": "value-b",
				},
			}), nil),
		},
		{
			Name: "otel set",
			Into: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"a": "value-a",
				},
			}), nil),
			From: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"b": "value-b",
				},
			}), confmap.NewFromStringMap(map[string]interface{}{
				"extensions": []interface{}{"health_check", "pprof"},
			})),
			Result: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"a": "value-a",
					"b": "value-b",
				},
			}), confmap.NewFromStringMap(map[string]interface{}{
				"extensions": []interface{}{"health_check", "pprof"},
			})),
		},
		{
			Name: "otel merge",
			Into: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"a": "value-a",
				},
			}), confmap.NewFromStringMap(map[string]interface{}{
				"extensions": []interface{}{"health_check", "pprof"},
			})),
			From: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"b": "value-b",
				},
			}), confmap.NewFromStringMap(map[string]interface{}{
				"receivers": map[string]interface{}{
					"filelog": map[string]interface{}{},
				},
			})),
			Result: newConfigFrom(ucfg.MustNewFrom(map[string]interface{}{
				"agent": map[string]interface{}{
					"a": "value-a",
					"b": "value-b",
				},
			}), confmap.NewFromStringMap(map[string]interface{}{
				"extensions": []interface{}{"health_check", "pprof"},
				"receivers": map[string]interface{}{
					"filelog": map[string]interface{}{},
				},
			})),
		},
	}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			err := s.Into.Merge(s.From)
			require.NoError(t, err)
			assert.Equal(t, s.Result, s.Into)
		})
	}
}

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
	"gopkg.in/yaml.v2"
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
				"username": "elastic",
				"password": "changeme",
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

	tmp, err := os.MkdirTemp("", "config")
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

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
	tmp, err := os.MkdirTemp("", "watch")
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

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

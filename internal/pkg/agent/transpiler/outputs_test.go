// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderOutputs(t *testing.T) {
	testcases := map[string]struct {
		input    Node
		expected Node
		vars     *Vars
		err      bool
	}{
		"outputs not dict": {
			input: NewKey("outputs", NewStrVal("not dict")),
			err:   true,
			vars:  mustMakeVars(map[string]interface{}{}),
		},
		"missing variable error": {
			input: NewKey("outputs", NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("${var1.missing}")),
				})),
			})),
			err: true,
			vars: mustMakeVars(map[string]interface{}{
				"var1": map[string]interface{}{
					"name": "value1",
				},
			}),
		},
		"bad variable error": {
			input: NewKey("outputs", NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name|'missing ending quote}")),
				})),
			})),
			err: true,
			vars: mustMakeVars(map[string]interface{}{
				"var1": map[string]interface{}{
					"name": "value1",
				},
			}),
		},
		"basic single var": {
			input: NewKey("outputs", NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name}")),
				})),
			})),
			expected: NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
				})),
			}),
			vars: mustMakeVars(map[string]interface{}{
				"var1": map[string]interface{}{
					"name": "value1",
				},
			}),
		},
		"basic default var": {
			input: NewKey("outputs", NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("${var1.missing|'default'}")),
				})),
			})),
			expected: NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("default")),
				})),
			}),
			vars: mustMakeVars(map[string]interface{}{
				"var1": map[string]interface{}{
					"name": "value1",
				},
			}),
		},
		"basic no provider var": {
			input: NewKey("outputs", NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("${name}")),
				})),
			})),
			expected: NewDict([]Node{
				NewKey("default", NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
				})),
			}),
			vars: mustMakeVarsWithDefault(map[string]interface{}{
				"var1": map[string]interface{}{
					"name": "value1",
				},
			}, "var1"),
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			v, err := RenderOutputs(test.input, []*Vars{test.vars})
			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected.String(), v.String())
			}
		})
	}
}

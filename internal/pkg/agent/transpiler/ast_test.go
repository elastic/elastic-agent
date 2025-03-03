// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/cespare/xxhash/v2"

	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/elastic-agent/internal/pkg/eql"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestAST(t *testing.T) {
	testcases := map[string]struct {
		hashmap     map[string]interface{}
		expectedMap map[string]interface{}
		ast         *AST
	}{
		"simple slice/string": {
			hashmap: map[string]interface{}{
				"inputs": []map[string]interface{}{
					map[string]interface{}{
						"paths": []string{"/var/log/log1", "/var/log/log2"},
					},
					map[string]interface{}{
						"paths": []string{"/var/log/log1", "/var/log/log2"},
					},
				},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "inputs", value: &List{
							value: []Node{
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
							},
						},
						},
					},
				},
			},
		},
		"special characters in strings": {
			hashmap: map[string]interface{}{
				"key":            "$1$$2$$$3$$$$4",
				"$1$$2$$$3$$$$4": "value",
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "key", value: &StrVal{value: "$1$$2$$$3$$$$4"}},
						&Key{name: "$1$$2$$$3$$$$4", value: &StrVal{value: "value"}},
					},
				},
			},
		},
		"integer as key": {
			hashmap: map[string]interface{}{
				"1": []string{"/var/log/log1", "/var/log/log2"},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "1", value: &List{value: []Node{
							&StrVal{value: "/var/log/log1"},
							&StrVal{value: "/var/log/log2"},
						}}},
					},
				},
			},
		},
		"support null (nil) values": {
			hashmap: map[string]interface{}{
				"nil_v": nil,
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "nil_v"},
					},
				},
			},
		},
		"support bool": {
			hashmap: map[string]interface{}{
				"true_v":  true,
				"false_v": false,
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "false_v", value: &BoolVal{value: false}},
						&Key{name: "true_v", value: &BoolVal{value: true}},
					},
				},
			},
		},
		"support integers": {
			hashmap: map[string]interface{}{
				"timeout": 12,
				"zero":    int64(0),
				"range":   []int{20, 30, 40},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "range",
							value: NewList(
								[]Node{
									&IntVal{value: 20},
									&IntVal{value: 30},
									&IntVal{value: 40},
								},
							),
						},
						&Key{name: "timeout", value: &IntVal{value: 12}},
						&Key{name: "zero", value: &IntVal{value: 0}},
					},
				},
			},
		},
		"support unsigned integers": {
			hashmap: map[string]interface{}{
				"timeout": 12,
				"range":   []uint64{20, 30, 40},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "range",
							value: NewList(
								[]Node{
									&UIntVal{value: uint64(20)},
									&UIntVal{value: uint64(30)},
									&UIntVal{value: uint64(40)},
								},
							),
						},
						&Key{name: "timeout", value: &IntVal{value: 12}},
					},
				},
			},
		},
		"support floats": {
			hashmap: map[string]interface{}{
				"ratio":   0.5,
				"range64": []float64{20.0, 30.0, 40.0},
				"range32": []float32{20.0, 30.0, 40.0},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "range32",
							value: NewList(
								[]Node{
									&FloatVal{value: 20.0},
									&FloatVal{value: 30.0},
									&FloatVal{value: 40.0},
								},
							),
						},
						&Key{
							name: "range64",
							value: NewList(
								[]Node{
									&FloatVal{value: 20.0},
									&FloatVal{value: 30.0},
									&FloatVal{value: 40.0},
								},
							),
						},
						&Key{name: "ratio", value: &FloatVal{value: 0.5}},
					},
				},
			},
		},
		"Keys inside Keys with slices": {
			hashmap: map[string]interface{}{
				"inputs": map[string]interface{}{
					"type":         "log/docker",
					"ignore_older": "20s",
					"paths":        []string{"/var/log/log1", "/var/log/log2"},
				},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "inputs",
							value: NewDict(
								[]Node{
									&Key{name: "ignore_older", value: &StrVal{value: "20s"}},
									&Key{name: "paths", value: &List{value: []Node{
										&StrVal{value: "/var/log/log1"},
										&StrVal{value: "/var/log/log2"},
									}}},
									&Key{name: "type", value: &StrVal{value: "log/docker"}},
								}),
						},
					},
				},
			},
		},
		"Keys with multiple levels of deeps": {
			hashmap: map[string]interface{}{
				"inputs": map[string]interface{}{
					"type":         "log/docker",
					"ignore_older": "20s",
					"paths":        []string{"/var/log/log1", "/var/log/log2"},
				},
				"outputs": map[string]interface{}{
					"elasticsearch": map[string]interface{}{
						"ssl": map[string]interface{}{
							"certificates_authorities": []string{"abc1", "abc2"},
						},
					},
				},
			},
			ast: &AST{
				root: NewDict(
					[]Node{
						&Key{
							name: "inputs",
							value: NewDict(
								[]Node{
									&Key{name: "ignore_older", value: &StrVal{value: "20s"}},
									&Key{name: "paths", value: &List{value: []Node{
										&StrVal{value: "/var/log/log1"},
										&StrVal{value: "/var/log/log2"},
									}}},
									&Key{name: "type", value: &StrVal{value: "log/docker"}},
								}),
						},
						&Key{
							name: "outputs",
							value: NewDict(
								[]Node{
									&Key{
										name: "elasticsearch",
										value: NewDict(
											[]Node{
												&Key{
													name: "ssl",
													value: NewDict(
														[]Node{
															&Key{name: "certificates_authorities",
																value: NewList(
																	[]Node{
																		&StrVal{value: "abc1"},
																		&StrVal{value: "abc2"},
																	},
																),
															},
														}),
												},
											}),
									},
								}),
						},
					}),
			},
		},
		"Keys with multiple levels of deeps with compact keys": {
			hashmap: map[string]interface{}{
				"inputs": map[string]interface{}{
					"type":         "log/docker",
					"ignore_older": "20s",
					"paths":        []string{"/var/log/log1", "/var/log/log2"},
				},
				"outputs.elasticsearch": map[string]interface{}{
					"ssl": map[string]interface{}{
						"certificates_authorities": []string{"abc1", "abc2"},
					},
				},
			},
			expectedMap: map[string]interface{}{
				"inputs": map[string]interface{}{
					"type":         "log/docker",
					"ignore_older": "20s",
					"paths":        []string{"/var/log/log1", "/var/log/log2"},
				},
				"outputs": map[string]interface{}{
					"elasticsearch": map[string]interface{}{
						"ssl": map[string]interface{}{
							"certificates_authorities": []string{"abc1", "abc2"},
						},
					},
				},
			},
			ast: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "inputs",
							value: NewDict(
								[]Node{
									&Key{name: "ignore_older", value: &StrVal{value: "20s"}},
									&Key{name: "paths", value: &List{value: []Node{
										&StrVal{value: "/var/log/log1"},
										&StrVal{value: "/var/log/log2"},
									}}},
									&Key{name: "type", value: &StrVal{value: "log/docker"}},
								}),
						},
						&Key{
							name: "outputs",
							value: NewDict(
								[]Node{
									&Key{
										name: "elasticsearch",
										value: NewDict(
											[]Node{
												&Key{
													name: "ssl",
													value: NewDict(
														[]Node{
															&Key{name: "certificates_authorities",
																value: NewList(
																	[]Node{
																		&StrVal{value: "abc1"},
																		&StrVal{value: "abc2"},
																	},
																),
															},
														}),
												},
											}),
									},
								}),
						},
					},
				},
			},
		},
	}

	t.Run("MAP to AST", func(t *testing.T) {
		for name, test := range testcases {
			t.Run(name, func(t *testing.T) {
				v, err := NewAST(test.hashmap)
				require.NoError(t, err)
				if !assert.True(t, yamlComparer(test.ast, v)) {
					diff := cmp.Diff(test.ast, v)
					t.Logf("Mismatch (-want, +got)\n%s", diff)
				}
			})
		}
	})

	t.Run("AST to MAP", func(t *testing.T) {
		for name, test := range testcases {
			t.Run(name, func(t *testing.T) {
				visitor := &MapVisitor{}
				test.ast.Accept(visitor)

				expectedMap := test.hashmap
				if test.expectedMap != nil {
					expectedMap = test.expectedMap
				}

				if !assert.True(t, yamlComparer(expectedMap, visitor.Content)) {
					diff := cmp.Diff(test.hashmap, visitor.Content)
					t.Logf("Mismatch (-want, +got)\n%s", diff)
				}
			})
		}
	})
}

func TestInsert(t *testing.T) {
	testcases := map[string]struct {
		hashmap  map[string]interface{}
		selector Selector
		node     Node
		expected *AST
	}{
		"insert root": {
			selector: "inputs",
			node: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("test-key")),
				}),
			}),
			hashmap: map[string]interface{}{
				"outputs": map[string]interface{}{
					"type": "elasticsearch",
					"host": "demo.host.co",
				},
			},
			expected: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "inputs",
							value: NewList([]Node{
								NewDict([]Node{
									NewKey("type", NewStrVal("test-key")),
								}),
							}),
						},
						&Key{
							name: "outputs",
							value: NewDict(
								[]Node{
									&Key{name: "host", value: &StrVal{value: "demo.host.co"}},
									&Key{name: "type", value: &StrVal{value: "elasticsearch"}},
								}),
						},
					},
				},
			},
		},
		"insert sub key": {
			selector: "outputs.sub",
			node: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("test-key")),
				}),
			}),
			hashmap: map[string]interface{}{
				"outputs": map[string]interface{}{
					"type": "elasticsearch",
					"host": "demo.host.co",
				},
			},
			expected: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "outputs",
							value: NewDict(
								[]Node{
									&Key{name: "host", value: &StrVal{value: "demo.host.co"}},
									&Key{name: "sub", value: NewList([]Node{
										NewDict([]Node{
											NewKey("type", NewStrVal("test-key")),
										}),
									})},
									&Key{name: "type", value: &StrVal{value: "elasticsearch"}},
								}),
						},
					},
				},
			},
		},
		"insert at index": {
			selector: "inputs.0.sub",
			node: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("test-key")),
				}),
			}),
			hashmap: map[string]interface{}{
				"inputs": []interface{}{
					map[string]interface{}{
						"type":         "log/docker",
						"ignore_older": "20s",
					},
				},
			},
			expected: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "inputs",
							value: NewList(
								[]Node{
									NewDict([]Node{
										NewKey("ignore_older", NewStrVal("20s")),
										NewKey("sub", NewList([]Node{
											NewDict([]Node{
												NewKey("type", NewStrVal("test-key")),
											}),
										})),
										NewKey("type", NewStrVal("log/docker")),
									}),
								}),
						},
					},
				},
			},
		},

		"insert at index when array empty": {
			selector: "inputs.0.sub",
			node: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("test-key")),
				}),
			}),
			hashmap: map[string]interface{}{
				"inputs": make([]interface{}, 0),
				"outputs": map[string]interface{}{
					"type": "elasticsearch",
					"host": "demo.host.co",
				},
			},
			expected: &AST{
				root: &Dict{
					value: []Node{
						&Key{
							name: "inputs",
							value: NewList(
								[]Node{
									NewDict(
										[]Node{
											NewKey("sub", NewList([]Node{
												NewDict([]Node{
													NewKey("type", NewStrVal("test-key")),
												}),
											})),
										},
									),
								}),
						},
						&Key{
							name: "outputs",
							value: NewDict(
								[]Node{
									NewKey("host", &StrVal{value: "demo.host.co"}),
									NewKey("type", &StrVal{value: "elasticsearch"}),
								}),
						},
					},
				},
			},
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			ast, err := NewAST(test.hashmap)
			require.NoError(t, err)

			err = Insert(ast, test.node, test.selector)
			require.NoError(t, err)

			if !assert.True(t, reflect.DeepEqual(test.expected, ast)) {
				t.Logf(
					`received: %+v
					 expected: %+v`, ast, test.expected)
			}

		})
	}
}

func yamlComparer(expected, candidate interface{}) bool {
	expectedYAML, err := yaml.Marshal(&expected)
	if err != nil {
		return false
	}

	candidateYAML, err := yaml.Marshal(&candidate)
	if err != nil {
		return false
	}

	return bytes.Equal(expectedYAML, candidateYAML)
}

func TestASTToMapStr(t *testing.T) {
	ast := &AST{
		root: &Dict{
			value: []Node{
				&Key{name: "inputs", value: &List{
					value: []Node{
						&Dict{
							value: []Node{
								&Key{name: "paths", value: &List{value: []Node{
									&StrVal{value: "/var/log/log1"},
									&StrVal{value: "/var/log/log2"},
								}}},
							},
						},
						&Dict{
							value: []Node{
								&Key{name: "paths", value: &List{value: []Node{
									&StrVal{value: "/var/log/log1"},
									&StrVal{value: "/var/log/log2"},
								}}},
							},
						},
					},
				},
				},
			},
		},
	}

	m, err := ast.Map()
	require.NoError(t, err)

	expected := map[string]interface{}{
		"inputs": []interface{}{
			map[string]interface{}{
				"paths": []interface{}{"/var/log/log1", "/var/log/log2"},
			},
			map[string]interface{}{
				"paths": []interface{}{"/var/log/log1", "/var/log/log2"},
			},
		},
	}

	assert.True(t, reflect.DeepEqual(m, expected))
}

func TestHash(t *testing.T) {
	tests := map[string]struct {
		c1    *AST
		c2    *AST
		match bool
	}{
		"same ast must match": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "inputs", value: &List{
							value: []Node{
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
							},
						},
						},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "inputs", value: &List{
							value: []Node{
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
							},
						},
						},
					},
				},
			},
			match: true,
		},
		"slice reordering doesn't match": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "inputs", value: &List{
							value: []Node{
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log2"},
											&StrVal{value: "/var/log/log1"},
										}}},
									},
								},
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
							},
						},
						},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "inputs", value: &List{
							value: []Node{
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
								&Dict{
									value: []Node{
										&Key{name: "paths", value: &List{value: []Node{
											&StrVal{value: "/var/log/log1"},
											&StrVal{value: "/var/log/log2"},
										}}},
									},
								},
							},
						},
						},
					},
				},
			},
			match: false,
		},
		"match with int / float / bool": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "integer", value: &IntVal{value: 1}},
						&Key{name: "float", value: &FloatVal{value: 1.1234}},
						&Key{name: "bool1", value: &BoolVal{value: true}},
						&Key{name: "bool2", value: &BoolVal{value: false}},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "integer", value: &IntVal{value: 1}},
						&Key{name: "float", value: &FloatVal{value: 1.1234}},
						&Key{name: "bool1", value: &BoolVal{value: true}},
						&Key{name: "bool2", value: &BoolVal{value: false}},
					},
				},
			},
			match: true,
		},
		"different bool don't match": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &BoolVal{value: true}},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &BoolVal{value: false}},
					},
				},
			},
			match: false,
		},
		"different integer don't match": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &IntVal{value: 1}},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &IntVal{value: 2}},
					},
				},
			},
			match: false,
		},
		"different float don't match": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &FloatVal{value: 1.0}},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &FloatVal{value: 2.0}},
					},
				},
			},
			match: false,
		},
		"different floats representing the same value match": {
			c1: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &IntVal{value: 1}},
					},
				},
			},
			c2: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "v", value: &FloatVal{value: 1.0}},
					},
				},
			},
			match: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.match, test.c1.Equal(test.c2))
		})

		t.Run("test base64 string", func(t *testing.T) {
			assert.Equal(t, test.match, test.c1.HashStr() == test.c2.HashStr())
		})
	}
}

func TestApplyDoesNotMutate(t *testing.T) {
	tests := map[string]struct {
		input Node
	}{
		"dict": {
			&Dict{
				value: []Node{
					&Key{name: "str", value: &StrVal{value: "${var}"}},
				},
			},
		},
		"list": {
			&List{
				value: []Node{
					&StrVal{value: "${var}"},
				},
			},
		},
		"key": {
			&Key{name: "str", value: &StrVal{value: "${var}"}},
		},
		"str": {&StrVal{value: "${var}"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			vars, err := NewVars("", map[string]any{"var": "value"}, mapstr.M{}, "")
			require.NoError(t, err)
			applied, err := test.input.Apply(vars)
			require.NoError(t, err)
			assert.NotEqual(t, test.input, applied)
		})
	}
}

func TestShallowClone(t *testing.T) {
	tests := map[string]struct {
		input *AST
	}{
		"dict": {
			input: &AST{
				root: &Dict{
					value: []Node{
						&Key{name: "integer", value: &IntVal{value: 1}},
						&Key{name: "float", value: &FloatVal{value: 1.1234}},
						&Key{name: "bool1", value: &BoolVal{value: true}},
					},
				},
			},
		},
		"list": {
			input: &AST{
				root: &List{
					value: []Node{
						&IntVal{value: 1},
						&FloatVal{value: 1.1234},
						&BoolVal{value: true},
					},
				},
			},
		},
		"key": {
			input: &AST{
				root: &Key{name: "integer", value: &IntVal{value: 1}},
			},
		},
		"str": {
			input: &AST{
				root: &StrVal{value: "value"},
			},
		},
		"bool": {
			input: &AST{
				root: &BoolVal{value: true},
			},
		},
		"integer": {
			input: &AST{
				root: &IntVal{value: 1},
			},
		},
		"float": {
			input: &AST{
				root: &FloatVal{value: 1.1234},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cloned := test.input.ShallowClone()
			assert.Equal(t, test.input, cloned)
			err := test.input.Insert(&AST{root: &Key{name: "integer", value: &IntVal{value: 7}}}, "integer")
			if err == nil {
				assert.NotEqual(t, test.input, cloned)
			} else if list, ok := test.input.root.(*List); ok {
				list.value = append(list.value, &IntVal{value: 7})
				assert.NotEqual(t, test.input, cloned)
			}
		})
	}
}

func TestVars(t *testing.T) {
	tests := map[string]struct {
		input           map[string]interface{}
		result          []string
		defaultProvider string
	}{
		"empty": {
			input:  map[string]interface{}{},
			result: nil,
		},
		"badbracket": {
			input: map[string]interface{}{
				"badbracket": "${missing.end",
			},
			result: nil,
		},
		"allconstant": {
			input: map[string]interface{}{
				"constant": "${'constant'}",
			},
			result: nil,
		},
		"escaped": {
			input: map[string]interface{}{
				"constant": "$${var1}",
			},
			result: nil,
		},
		"nested": {
			input: map[string]interface{}{
				"novars": map[string]interface{}{
					"list1": []interface{}{
						map[string]interface{}{
							"int":   1,
							"float": 1.1234,
							"bool":  true,
							"str":   "value1",
						},
					},
					"list2": []interface{}{
						map[string]interface{}{
							"int":   2,
							"float": 2.3456,
							"bool":  false,
							"str":   "value2",
						},
					},
				},
				"vars1": map[string]interface{}{
					"list1": []interface{}{
						map[string]interface{}{
							"int":   1,
							"float": 1.1234,
							"bool":  true,
							"str":   "${var1|var2|'constant'}",
						},
					},
					"list2": []interface{}{
						map[string]interface{}{
							"int":   2,
							"float": 2.3456,
							"bool":  false,
							"str":   "${var3|var1|'constant'}",
						},
					},
				},
				"vars2": map[string]interface{}{
					"list1": []interface{}{
						map[string]interface{}{
							"int":   1,
							"float": 1.1234,
							"bool":  true,
							"str":   "${var5|var6|'constant'}",
						},
					},
					"list2": []interface{}{
						map[string]interface{}{
							"int":   2,
							"float": 2.3456,
							"bool":  false,
							"str":   "${var1}",
						},
					},
				},
			},
			result: []string{"var1", "var2", "var3", "var1", "var5", "var6", "var1"},
		},
		"nested with default": {
			input: map[string]interface{}{
				"novars": map[string]interface{}{
					"list1": []interface{}{
						map[string]interface{}{
							"int":   1,
							"float": 1.1234,
							"bool":  true,
							"str":   "value1",
						},
					},
					"list2": []interface{}{
						map[string]interface{}{
							"int":   2,
							"float": 2.3456,
							"bool":  false,
							"str":   "value2",
						},
					},
				},
				"vars1": map[string]interface{}{
					"list1": []interface{}{
						map[string]interface{}{
							"int":   1,
							"float": 1.1234,
							"bool":  true,
							"str":   "${custom.var1|host.var2|'constant'}",
						},
					},
					"list2": []interface{}{
						map[string]interface{}{
							"int":   2,
							"float": 2.3456,
							"bool":  false,
							"str":   "${var3|custom.var1|'constant'}",
						},
					},
				},
				"vars2": map[string]interface{}{
					"list1": []interface{}{
						map[string]interface{}{
							"int":   1,
							"float": 1.1234,
							"bool":  true,
							"str":   "${host.var5|host.var6|'constant'}",
						},
					},
					"list2": []interface{}{
						map[string]interface{}{
							"int":   2,
							"float": 2.3456,
							"bool":  false,
							"str":   "${var1}",
						},
					},
				},
			},
			result:          []string{"custom.var1", "host.var2", "custom.var3", "custom.var1", "host.var5", "host.var6", "custom.var1"},
			defaultProvider: "custom",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ast, err := NewAST(test.input)
			require.NoError(t, err)
			var vars []string
			vars = ast.root.Vars(vars, test.defaultProvider)
			assert.Equal(t, test.result, vars)
		})
	}
}

func TestLookup(t *testing.T) {
	tests := map[string]struct {
		ast      *AST
		selector Selector
		node     Node
		ok       bool
	}{
		"nil": {
			ast:      nil,
			selector: "",
			node:     nil,
			ok:       false,
		},
		"noroot": {
			ast:      &AST{},
			selector: "",
			node:     nil,
			ok:       false,
		},
		"notfound": {
			ast: &AST{
				root: NewDict([]Node{NewKey("entry", NewDict([]Node{
					NewKey("var1", NewStrVal("value1")),
					NewKey("var2", NewStrVal("value2")),
				}))}),
			},
			selector: "entry.var3",
			node:     nil,
			ok:       false,
		},
		"found": {
			ast: &AST{
				root: NewDict([]Node{NewKey("entry", NewDict([]Node{
					NewKey("var1", NewStrVal("value1")),
					NewKey("var2", NewStrVal("value2")),
				}))}),
			},
			selector: "entry.var2",
			node:     NewKey("var2", NewStrVal("value2")),
			ok:       true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			node, ok := Lookup(test.ast, test.selector)
			if assert.Equal(t, test.ok, ok) {
				assert.Equal(t, test.node, node)
			}
		})
	}
}

func TestCondition(t *testing.T) {
	vars := mustMakeVars(map[string]interface{}{
		"other": map[string]interface{}{
			"data": "info",
		}})

	input := NewKey("condition", NewStrVal("${other.data} == 'info'"))
	expected := NewKey("condition", NewBoolVal(true))

	// the condition string hasn't been parsed yet
	assert.Nil(t, input.condition)

	output, err := input.Apply(vars)
	require.NoError(t, err)
	assert.Equal(t, expected, output)

	// check if the condition was parsed and cached
	assert.NotNil(t, input.condition)
	condition, err := eql.New(input.value.Value().(string))
	require.NoError(t, err)
	assert.Equal(t, condition, input.condition)

	// create a dict with the key
	dict := NewDict([]Node{input})
	ast := &AST{root: NewKey("key", dict)}
	// the cached condition remains
	assert.Equal(t, condition, input.condition)

	// replace the key with a new one, without a cached condition
	input2 := NewKey("condition", NewStrVal("${other.data} == 'info'"))
	err = Insert(ast, input2, "")
	require.NoError(t, err)
	assert.Nil(t, input2.condition)
}

// check that all the methods handle nil values correctly
func TestNullValues(t *testing.T) {
	cfgMap := map[string]any{
		"inputs": map[string]any{
			"dict": map[string]any{
				"key": nil,
			},
			"list": []any{nil},
		},
	}
	ast, err := NewAST(cfgMap)
	require.NoError(t, err)
	inputs, ok := Lookup(ast, "inputs")
	require.True(t, ok)

	assert.NotEmpty(t, inputs.String())

	node, ok := inputs.Find("dict")
	assert.True(t, ok)
	assert.NotNil(t, node)

	assert.NotNil(t, inputs.Value())

	assert.NotNil(t, inputs.Clone())

	assert.NotNil(t, inputs.ShallowClone())

	assert.NotEmpty(t, inputs.Hash())

	h := xxhash.New()
	err = inputs.Hash64With(h)
	assert.NoError(t, err)
	assert.NotEmpty(t, h.Sum64())

	assert.Empty(t, inputs.Vars([]string{}, "default"))

	newNode, err := inputs.Apply(nil)
	assert.NoError(t, err)
	assert.NotNil(t, newNode)

	assert.Empty(t, inputs.Processors())
}

func mustMakeVars(mapping map[string]interface{}) *Vars {
	v, err := NewVars("", mapping, nil, "")
	if err != nil {
		panic(err)
	}
	return v
}

func mustMakeVarsWithDefault(mapping map[string]interface{}, defaultProvider string) *Vars {
	v, err := NewVars("", mapping, nil, defaultProvider)
	if err != nil {
		panic(err)
	}
	return v
}

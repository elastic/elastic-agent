// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderInputs(t *testing.T) {
	testcases := map[string]struct {
		input     Node
		expected  Node
		varsArray []*Vars
		err       bool
	}{
		"inputs not list": {
			input: NewKey("inputs", NewStrVal("not list")),
			err:   true,
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{}),
			},
		},
		"bad variable error": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name|'missing ending quote}")),
				}),
			})),
			err: true,
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				}),
			},
		},
		"basic single var": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name}")),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				}),
			},
		},
		"duplicate result is removed": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name}")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.diff}")),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value1",
					},
				}),
			},
		},
		"missing var removes input": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name}")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.missing|var1.diff}")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.removed}")),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value1",
					},
				}),
			},
		},
		"duplicate var result but unique input not removed": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name}")),
					NewKey("unique", NewStrVal("0")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.diff}")),
					NewKey("unique", NewStrVal("1")),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
					NewKey("unique", NewStrVal("0")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
					NewKey("unique", NewStrVal("1")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value1",
					},
				}),
			},
		},
		"duplicates across vars array handled": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.name}")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("${var1.diff}")),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("key", NewStrVal("value1")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("value2")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("value3")),
				}),
				NewDict([]Node{
					NewKey("key", NewStrVal("value4")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value1",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value2",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value3",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value2",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
						"diff": "value4",
					},
				}),
			},
		},
		"nested in streams": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
						}),
					})),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value1.log"),
							})),
						}),
					})),
				}),
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value2.log"),
							})),
						}),
					})),
				}),
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value3.log"),
							})),
						}),
					})),
				}),
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value4.log"),
							})),
						}),
					})),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value2",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value2",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value3",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value4",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"missing": "other",
					},
				}),
			},
		},
		"inputs with processors": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
						}),
					})),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("user", NewStrVal("user1")),
								})),
								NewKey("to", NewStrVal("user")),
							})),
						}),
					})),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value1.log"),
							})),
						}),
					})),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("user", NewStrVal("user1")),
								})),
								NewKey("to", NewStrVal("user")),
							})),
						}),
					})),
				}),
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value2.log"),
							})),
						}),
					})),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("user", NewStrVal("user1")),
								})),
								NewKey("to", NewStrVal("user")),
							})),
						}),
					})),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				}),
				mustMakeVars(map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value2",
					},
				}),
			},
		},
		"vars with processors": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("id", NewStrVal("initial")),
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
						}),
					})),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("user", NewStrVal("user1")),
								})),
								NewKey("to", NewStrVal("user")),
							})),
						}),
					})),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("id", NewStrVal("initial-value1")),
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value1.log"),
							})),
						}),
					})),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("custom", NewStrVal("value1")),
								})),
								NewKey("to", NewStrVal("dynamic")),
							})),
						}),
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("user", NewStrVal("user1")),
								})),
								NewKey("to", NewStrVal("user")),
							})),
						}),
					})),
					NewKey("original_id", NewStrVal("initial")),
				}),
				NewDict([]Node{
					NewKey("id", NewStrVal("initial-value2")),
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value2.log"),
							})),
						}),
					})),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("custom", NewStrVal("value2")),
								})),
								NewKey("to", NewStrVal("dynamic")),
							})),
						}),
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("user", NewStrVal("user1")),
								})),
								NewKey("to", NewStrVal("user")),
							})),
						}),
					})),
					NewKey("original_id", NewStrVal("initial")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVarsP("value1", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value1",
								},
								"to": "dynamic",
							},
						},
					}),
				mustMakeVarsP("value2", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value2",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value2",
								},
								"to": "dynamic",
							},
						},
					}),
			},
		},
		"inputs without processors and vars with processors": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
						}),
					})),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value1.log"),
							})),
						}),
					})),
					NewKey("id", NewStrVal("value1")),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("custom", NewStrVal("value1")),
								})),
								NewKey("to", NewStrVal("dynamic")),
							})),
						}),
					})),
				}),
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value2.log"),
							})),
						}),
					})),
					NewKey("id", NewStrVal("value2")),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("custom", NewStrVal("value2")),
								})),
								NewKey("to", NewStrVal("dynamic")),
							})),
						}),
					})),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVarsP("value1", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value1",
								},
								"to": "dynamic",
							},
						},
					}),
				mustMakeVarsP("value2", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value2",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value2",
								},
								"to": "dynamic",
							},
						},
					}),
			},
		},
		"processors incorrectly a map": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
						}),
					})),
					NewKey("processors", NewDict([]Node{
						NewKey("add_fields", NewDict([]Node{
							NewKey("invalid", NewStrVal("value")),
						})),
					})),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value1.log"),
							})),
						}),
					})),
					NewKey("processors", NewDict([]Node{
						NewKey("add_fields", NewDict([]Node{
							NewKey("invalid", NewStrVal("value")),
						})),
					})),
					NewKey("id", NewStrVal("value1")),
				}),
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value2.log"),
							})),
						}),
					})),
					NewKey("processors", NewDict([]Node{
						NewKey("add_fields", NewDict([]Node{
							NewKey("invalid", NewStrVal("value")),
						})),
					})),
					NewKey("id", NewStrVal("value2")),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVarsP("value1", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value1",
								},
								"to": "dynamic",
							},
						},
					}),
				mustMakeVarsP("value2", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value2",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value2",
								},
								"to": "dynamic",
							},
						},
					}),
			},
		},
		"same var result with different processors": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
						}),
					})),
				}),
			})),
			expected: NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/value1.log"),
							})),
						}),
					})),
					NewKey("id", NewStrVal("value1")),
					NewKey("processors", NewList([]Node{
						NewDict([]Node{
							NewKey("add_fields", NewDict([]Node{
								NewKey("fields", NewDict([]Node{
									NewKey("custom", NewStrVal("value1")),
								})),
								NewKey("to", NewStrVal("dynamic")),
							})),
						}),
					})),
				}),
			}),
			varsArray: []*Vars{
				mustMakeVarsP("value1", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value1",
								},
								"to": "dynamic",
							},
						},
					}),
				mustMakeVarsP("value2", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					[]map[string]interface{}{
						{
							"add_fields": map[string]interface{}{
								"fields": map[string]interface{}{
									"custom": "value2",
								},
								"to": "dynamic",
							},
						},
					}),
			},
		},
		"input removal with stream conditions": {
			input: NewKey("inputs", NewList([]Node{
				NewDict([]Node{
					NewKey("type", NewStrVal("logfile")),
					NewKey("streams", NewList([]Node{
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
							NewKey("condition", NewStrVal("${var1.name} != 'value1'")),
						}),
						NewDict([]Node{
							NewKey("paths", NewList([]Node{
								NewStrVal("/var/log/${var1.name}.log"),
							})),
							NewKey("condition", NewStrVal("${var1.name} != 'value1'")),
						}),
					})),
				}),
			})),
			expected: NewList([]Node{}),
			varsArray: []*Vars{
				mustMakeVarsP("value1", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					nil),
				mustMakeVarsP("value2", map[string]interface{}{
					"var1": map[string]interface{}{
						"name": "value1",
					},
				},
					"var1",
					nil),
			},
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			v, err := RenderInputs(test.input, test.varsArray)
			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected.String(), v.String())
			}
		})
	}
}

func mustMakeVarsP(id string, mapping map[string]interface{}, processorKey string, processors Processors) *Vars {
	v, err := NewVarsWithProcessors(id, mapping, processorKey, processors, nil)
	if err != nil {
		panic(err)
	}
	return v
}

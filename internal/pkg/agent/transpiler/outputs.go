// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"fmt"
)

// RenderOutputs renders outputs section.
//
// outputs are only rendered using the context variables and they do not support
// using dynamic provider variables.
func RenderOutputs(outputs Node, varsArray []*Vars) (Node, error) {
	if len(varsArray) == 0 {
		// no context vars (nothing to do)
		return outputs, nil
	}

	// outputs only operates on the first set of vars because those are always the
	// context provider variables and never include dynamic provider variables
	//
	// dynamic provider variables cannot be used for outputs as we don't want outputs
	// to be duplicated (unlike inputs)
	vars := varsArray[0]

	d, ok := outputs.Value().(*Dict)
	if !ok {
		return nil, fmt.Errorf("outputs must be an dict")
	}
	nodes := d.Value().([]Node)
	keys := make([]Node, len(nodes))
	for i, node := range nodes {
		key, ok := node.(*Key)
		if !ok {
			// not possible, but be defensive
			continue
		}
		if key.value == nil {
			keys[i] = key
			continue
		}
		dict, ok := key.value.(*Dict)
		if !ok {
			// not possible, but be defensive
			continue
		}
		// Apply creates a new Node with a deep copy of all the values
		var err error
		key.value, err = dict.Apply(vars)
		// inputs allows a variable not to match and it will be removed
		// outputs are not that way, if an ErrNoMatch is returned we
		// return it back to the caller
		if err != nil {
			// another error that needs to be reported
			return nil, err
		}
		keys[i] = key
	}
	return &Dict{keys, nil}, nil
}

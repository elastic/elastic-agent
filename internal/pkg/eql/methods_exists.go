// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eql

import (
	"fmt"
)

// exists returns true for any non-null argument, false for null.
func exists(args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("exists: accepts exactly 1 argument; received %d", len(args))
	}

	switch args[0].(type) {
	case *null:
		return false, nil
	default:
		return true, nil
	}
}

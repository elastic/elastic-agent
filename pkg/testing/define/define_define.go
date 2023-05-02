// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build define

package define

import (
	"encoding/json"
	"fmt"
	"testing"
)

func defineAction(t *testing.T, req Requirements) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		panic(fmt.Sprintf("test %s has invalid requirements: %s", t.Name(), err))
	}
	// skip recording the requirements for the test
	// this is picked up by the pre-processor to determine where the test will be executed
	data, err := json.Marshal(req)
	if err != nil {
		panic(fmt.Sprintf("test %s failed to marshal requirements: %s", t.Name(), err))
	}
	t.Skip(fmt.Sprintf("define skip; requirements: %s", data))
	return nil
}

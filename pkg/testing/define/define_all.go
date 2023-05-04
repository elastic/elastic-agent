// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !define && !local

package define

import (
	"fmt"
	"testing"
)

func defineAction(t *testing.T, req Requirements) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		panic(fmt.Sprintf("test %s has invalid requirements: %s", t.Name(), err))
	}
	namespace, err := getNamespace(t, "")
	if err != nil {
		panic(err)
	}
	info := &Info{
		Namespace: namespace,
	}
	if req.Stack != nil {
		info.ESClient, err = getESClient()
		if err != nil {
			panic(err)
		}
		info.KibanaClient, err = getKibanaClient()
		if err != nil {
			panic(err)
		}
	}
	return info
}

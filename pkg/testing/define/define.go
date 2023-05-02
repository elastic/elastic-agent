// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/go-elasticsearch/v8"
)

// Require defines what this test requires for it to be run by the test runner.
//
// This must be defined as the first line of a test, otherwise the test runner.
func Require(t *testing.T, req Requirements) *Info {
	return defineAction(t, req)
}

type Info struct {
	// ESClient is the elasticsearch client to communicate with elasticsearch.
	// This is only present if you say a cloud is required in the `define.Require`.
	ESClient *elasticsearch.Client

	// KibanaClient is the kibana client to communicate with kibana.
	// This is only present if you say a cloud is required in the `define.Require`.
	KibanaClient *kibana.Client

	// Namespace should be used for isolating data and actions per test.
	//
	// This is unique to each test and instance combination so a test that need to
	// read/write data to a data stream in elasticsearch do not collide.
	Namespace string
}

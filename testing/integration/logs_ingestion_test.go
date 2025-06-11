// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestLogIngestionFleetManaged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})
	LogIngestionFleetManaged(t, info)
}

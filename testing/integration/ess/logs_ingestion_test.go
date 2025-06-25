// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestLogIngestionFleetManaged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	integration.LogIngestionFleetManaged(t, info)
}

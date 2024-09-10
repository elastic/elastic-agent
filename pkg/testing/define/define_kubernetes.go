// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build kubernetes && !define && !local

package define

import (
	"testing"
)

func defineAction(t *testing.T, req Requirements) *Info {
	return runOrSkip(t, req, false, true)
}

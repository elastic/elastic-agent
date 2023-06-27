// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"fmt"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	inputsKey = "inputs"
)

func newInputsCapability(caps []*inputCapability) *multiInputsCapability {
	return &multiInputsCapability{caps: caps}
}

func (mic *multiInputsCapability) allowInput(inputType string) bool {
	for _, cap := range mic.caps {
		if matchesExpr(cap.Input, inputType) {
			// The check passed, allow or reject as appropriate
			return cap.Type == "allow"
		}
	}
	// If nothing blocked it, default to allow.
	return true
}

type inputCapability struct {
	log   *logger.Logger
	Name  string `json:"name,omitempty" yaml:"name,omitempty"`
	Type  string `json:"rule" yaml:"rule"`
	Input string `json:"input,omitempty" yaml:"input,omitempty"`
}

func (c *inputCapability) name() string {
	if c.Name != "" {
		return c.Name
	}

	t := "allow"
	if c.Type == denyKey {
		t = "deny"
	}

	// e.g IA(*) or ID(system/*)
	c.Name = fmt.Sprintf("I %s(%s)", t, c.Input)
	return c.Name
}

type multiInputsCapability struct {
	caps []*inputCapability
}

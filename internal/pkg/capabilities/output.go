// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	outputKey = "outputs"
	typeKey   = "type"
)

func newOutputsCapability(caps []*outputCapability) *multiOutputsCapability {
	return &multiOutputsCapability{caps: caps}
}

func (mic *multiOutputsCapability) allowOutput(outputType string) bool {
	for _, cap := range mic.caps {
		if matchesExpr(cap.Output, outputType) {
			// The check passed, allow or reject as appropriate
			return cap.Type == "allow"
		}
	}
	// If nothing blocked it, default to allow.
	return true
}

type outputCapability struct {
	log    *logger.Logger
	Name   string `json:"name,omitempty" yaml:"name,omitempty"`
	Type   string `json:"rule" yaml:"rule"`
	Output string `json:"output" yaml:"output"`
}

type multiOutputsCapability struct {
	caps []*outputCapability
}

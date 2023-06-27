// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

type inputCapability struct {
	Type  allowOrDeny `yaml:"rule"`
	Input string      `yaml:"input,omitempty"`
}

func allowInput(inputType string, inputCaps []*inputCapability) bool {
	for _, cap := range inputCaps {
		if matchesExpr(cap.Input, inputType) {
			// The check passed, allow or reject as appropriate
			return cap.Type == ruleTypeAllow
		}
	}
	// If nothing blocked it, default to allow.
	return true
}

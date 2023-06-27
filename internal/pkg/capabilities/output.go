// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

type outputCapability struct {
	Type   allowOrDeny `yaml:"rule"`
	Output string      `yaml:"output"`
}

func allowOutput(outputType string, outputCaps []*outputCapability) bool {
	for _, cap := range outputCaps {
		if matchesExpr(cap.Output, outputType) {
			// The check passed, allow or reject as appropriate
			return cap.Type == ruleTypeAllow
		}
	}
	// If nothing blocked it, default to allow.
	return true
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// policyInputsKey is the top-level policy key whose entries marshalPolicyYAML
// encodes one at a time.
const policyInputsKey = "inputs"

// inputsPlaceholder stands in for the top-level "inputs" list while
// marshalPolicyYAML encodes the rest of the policy. It is a plain scalar, so
// yaml.v3 emits it unquoted.
const inputsPlaceholder = "__elastic_agent_computed_config_inputs__"

// marshalPolicyYAML encodes inputs separately to limit peak memory because
// yaml.v3 retains event slots until Marshal returns.
// Its output matches yaml.Marshal(policy).
func marshalPolicyYAML(policy map[string]interface{}) ([]byte, error) {
	inputs, ok := policy[policyInputsKey].([]interface{})
	if !ok || len(inputs) == 0 {
		// No input list to split up (an empty list is emitted inline as "[]").
		return yaml.Marshal(policy)
	}

	rest := make(map[string]interface{}, len(policy))
	for k, v := range policy {
		rest[k] = v
	}
	rest[policyInputsKey] = inputsPlaceholder
	out, err := yaml.Marshal(rest)
	if err != nil {
		return nil, err
	}

	placeholder := []byte(policyInputsKey + ": " + inputsPlaceholder + "\n")
	at := bytes.Index(out, placeholder)
	if at < 0 || (at > 0 && out[at-1] != '\n') || bytes.Count(out, placeholder) != 1 {
		// Another value contains the placeholder text, so where to splice is
		// ambiguous.
		return yaml.Marshal(policy)
	}

	header := []byte(policyInputsKey + ":\n")
	var buf bytes.Buffer
	buf.Write(out[:at])
	buf.Write(header)
	for i, input := range inputs {
		// A one-entry list puts the input at the same column as in the full
		// document, so yaml.v3 folds long strings at the same points.
		in, err := yaml.Marshal(map[string]interface{}{policyInputsKey: []interface{}{input}})
		if err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(in, header) {
			return nil, fmt.Errorf("unexpected YAML encoding of %s[%d]", policyInputsKey, i)
		}
		buf.Write(in[len(header):])
	}
	buf.Write(out[at+len(placeholder):])
	return buf.Bytes(), nil
}

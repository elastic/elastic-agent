// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v2"
)

// policyInputsKey is the top-level policy key whose entries marshalPolicyYAML
// encodes one at a time.
const policyInputsKey = "inputs"

// inputsPlaceholder stands in for the top-level "inputs" list while
// marshalPolicyYAML encodes the rest of the policy. It is a plain scalar, so
// yaml.v2 emits it unquoted.
const inputsPlaceholder = "__elastic_agent_computed_config_inputs__"

// marshalPolicyYAML returns the same bytes as yaml.Marshal(policy), but never
// hands the encoder more than one entry of the top-level "inputs" list at a
// time.
//
// yaml.v2's emitter keeps every event of a document queued until Marshal
// returns, so encoding a policy with thousands of inputs (for example a
// Synthetics private location) in one call holds memory many times the size of
// the output and can get the agent OOM-killed while it collects diagnostics.
//
// The rest of the policy is encoded in one call with a placeholder in place of
// the inputs, and the inputs are spliced in where the placeholder lands, so
// yaml.v2 still decides the key order. The output stays byte-identical because
// yaml.v2 emits each entry of a block mapping or block sequence independently
// of its siblings. Each input is encoded inside a single-entry "inputs" list,
// so it is emitted at the same indentation and column as in the full document;
// this matters because yaml.v2 folds long strings at 80 columns.
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

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

// marshalPolicyYAML returns the same bytes as yaml.Marshal(policy), but never
// hands the encoder more than one top-level key, or more than one entry of the
// top-level "inputs" list, at a time.
//
// yaml.v2's emitter keeps every event of a document queued until Marshal
// returns, so encoding a policy with thousands of inputs (for example a
// Synthetics private location) in one call holds memory many times the size of
// the output and can get the agent OOM-killed while it collects diagnostics.
//
// The output stays byte-identical because yaml.v2 emits each entry of a block
// mapping or block sequence independently of its siblings. Each input is
// encoded inside a single-entry "inputs" list, so it is emitted at the same
// indentation and column as in the full document; this matters because yaml.v2
// folds long strings at 80 columns.
func marshalPolicyYAML(policy map[string]interface{}) ([]byte, error) {
	inputs, ok := policy[policyInputsKey].([]interface{})
	if !ok || len(inputs) == 0 {
		// No input list to split up (an empty list is emitted inline as "[]").
		return yaml.Marshal(policy)
	}

	keys, err := yamlKeyOrder(policy)
	if err != nil {
		return nil, err
	}

	header := []byte(policyInputsKey + ":\n")
	var buf bytes.Buffer
	for _, k := range keys {
		if k != policyInputsKey {
			out, err := yaml.Marshal(map[string]interface{}{k: policy[k]})
			if err != nil {
				return nil, err
			}
			buf.Write(out)
			continue
		}

		buf.Write(header)
		for i, input := range inputs {
			out, err := yaml.Marshal(map[string]interface{}{policyInputsKey: []interface{}{input}})
			if err != nil {
				return nil, err
			}
			if !bytes.HasPrefix(out, header) {
				return nil, fmt.Errorf("unexpected YAML encoding of %s[%d]", policyInputsKey, i)
			}
			buf.Write(out[len(header):])
		}
	}
	return buf.Bytes(), nil
}

// yamlKeyOrder returns the keys of m in the order yaml.Marshal emits them.
// yaml.v2 sorts map keys with its own unexported ordering, so rather than
// copying it, encode a map from each key to its index and decode the result in
// document order.
func yamlKeyOrder(m map[string]interface{}) ([]string, error) {
	keys := make([]string, 0, len(m))
	index := make(map[string]int, len(m))
	for k := range m {
		index[k] = len(keys)
		keys = append(keys, k)
	}

	out, err := yaml.Marshal(index)
	if err != nil {
		return nil, err
	}
	var ordered yaml.MapSlice
	if err := yaml.Unmarshal(out, &ordered); err != nil {
		return nil, err
	}
	if len(ordered) != len(keys) {
		return nil, fmt.Errorf("decoded %d policy keys, expected %d", len(ordered), len(keys))
	}

	sorted := make([]string, 0, len(keys))
	for _, item := range ordered {
		i, ok := item.Value.(int)
		if !ok || i < 0 || i >= len(keys) {
			return nil, fmt.Errorf("unexpected index %v for policy key %v", item.Value, item.Key)
		}
		sorted = append(sorted, keys[i])
	}
	return sorted, nil
}

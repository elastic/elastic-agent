// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package conv

import "fmt"

// YAMLMapToJSONMap changes the nested map[interface{}]interface{} to map[string]interface{} recursively

// This is needed to convert YAML deserializer result into a JSON compatible result
func YAMLMapToJSONMap(m map[string]interface{}) map[string]interface{} {
	return fixVal(m).(map[string]interface{})
}

func fixVal(m interface{}) interface{} {
	switch m := m.(type) {
	case map[interface{}]interface{}:
		return fixMap(m)
	case map[string]interface{}:
		for k, v := range m {
			m[k] = fixVal(v)
		}
		return m
	case []interface{}:
		return fixArray(m)
	}
	return m
}

func fixMap(in map[interface{}]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}

	out := make(map[string]interface{})
	for k, v := range in {
		sk, ok := k.(string)
		if !ok {
			sk = fmt.Sprint(k)
		}
		out[sk] = fixVal(v)
	}
	return out
}

func fixArray(in []interface{}) []interface{} {
	if in == nil {
		return nil
	}

	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = fixVal(v)
	}
	return out
}

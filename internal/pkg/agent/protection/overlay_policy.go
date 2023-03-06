// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

// overlayPolicy overlays/overwrites/appends the policy with the signed layer
func overlayPolicy(policy, signed map[string]interface{}) map[string]interface{} {
	if signed != nil && policy == nil {
		policy = make(map[string]interface{})
	}
	for k, v := range signed {
		policy[k] = overlayLevel(policy[k], v)
	}
	return policy
}

func overlayLevel(src, overlay interface{}) interface{} {
	switch v := overlay.(type) {
	case map[string]interface{}:
		m, ok := src.(map[string]interface{})
		if !ok {
			m = make(map[string]interface{})
		}

		for mk, mv := range v {
			m[mk] = overlayLevel(m[mk], mv)
		}

		return m
	}
	return overlay
}

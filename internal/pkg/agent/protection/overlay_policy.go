// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

// overlayPolicy overlays/overwrites/appends the policy with the signed layer
//
// With the policy signing introduction here, the only small portion of the policy is signed, the part that needs to be protected from tampering at the moment.
// The policy can't be signed as a whole at the source unfortunately, due to the fact that the fleet server modifies the policy before distributing it to the agents.
//
// As of March 9th, 2023 the "protection" part of the policy is signed:
//
//	{
//	    "agent": {
//			...
//	        "protection": {
//	            "enabled": true,
//	            "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A==",
//	            "uninstall_token_hash": "IKoZIzj0DAQcDQgAEqrEVMJBf"
//	        }
//			...
//	    },
//		...
//	}
//
// The signed data at the moment looks like this:
//
//	{
//	    "id": "681b1230-b798-11ed-8be1-47153ce217a7",
//	    "agent": {
//	        "protection": {
//	            "enabled": true,
//	            "uninstall_token_hash": "",
//	            "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A=="
//	        }
//	    }
//	}
//
// When the policy is signed the data above is serialized into the JSON bytes, signed and included in the policy as "signed" property by kibana:
//
//	"signed": {
//		"data": "eyJpZCI6IjY4MWIxMjMwLWI3OTgtMTFlZC04YmUxLTQ3MTUzY2UyMTdhNyIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXFyRVZNSkJmQWlXN016OVpIZWd3bEI3bjRkZVRBU1VhNUxsSmxEZnV6MGh4by83V1BjN2drVkI1SDhMZ25PYlBmaWhnek1MN3JMc0hQcmVXWlRCMTBBPT0ifX19",
//		"signature": "MEUCIQCdtCiVPHRUvvND5Btw7uuiXDku5ljWECEUnyYAQwMkSwIgM9cxkRjW56L7kG1fKH8t5zZeK7R02TKN8IsxgPZdWrs="
//	}
//
// The signed part of the policy is referred here as "signed" parameter, has exactly the same layout as a policy, starting from the root element.
// It includes the policy id to validate the match between the signed part and the policy.
// The matching structure allows it be easily overlayed on top of the policy after the signature and the policy id match is validated.
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

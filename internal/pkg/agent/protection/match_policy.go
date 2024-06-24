// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"errors"
	"fmt"
)

var (
	ErrMissingPolicyID     = errors.New("missing policy id")
	ErrInvalidPolicyIDType = errors.New("invalid policy id type")
	ErrMismatchedPolicyID  = errors.New("mismatched policy ids")
)

// isPolicyMatching returns a error if the signed data for the policy doesn't have the matching policy id
// The policy id is present at the top level of the policy and is included into the signed payload of the policy.
// For example the signed data from the policy:
//
//	"signed": {
//		"data": "eyJpZCI6IjY4MWIxMjMwLWI3OTgtMTFlZC04YmUxLTQ3MTUzY2UyMTdhNyIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXFyRVZNSkJmQWlXN016OVpIZWd3bEI3bjRkZVRBU1VhNUxsSmxEZnV6MGh4by83V1BjN2drVkI1SDhMZ25PYlBmaWhnek1MN3JMc0hQcmVXWlRCMTBBPT0ifX19",
//		"signature": "MEUCIQCdtCiVPHRUvvND5Btw7uuiXDku5ljWECEUnyYAQwMkSwIgM9cxkRjW56L7kG1fKH8t5zZeK7R02TKN8IsxgPZdWrs="
//	}
//
// The data is base64 encoded JSON:
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
// This data is referred here as the "signed layer" that contains the policy id at the top level, thus the function checks the if the policy id in the policy and in the "signed layer" match.
func isPolicyMatching(policy map[string]interface{}, signedLayer map[string]interface{}) error {
	policyID, err := getPolicyID(policy)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	signedPolicyID, err := getPolicyID(signedLayer)
	if err != nil {
		return fmt.Errorf("signed data: %w", err)
	}

	if policyID != signedPolicyID {
		return ErrMismatchedPolicyID
	}
	return nil
}

func getPolicyID(m map[string]interface{}) (string, error) {
	v, ok := m["id"]
	if !ok {
		return "", ErrMissingPolicyID
	}

	s, ok := v.(string)
	if !ok {
		return "", ErrInvalidPolicyIDType
	}

	return s, nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import "errors"

var (
	ErrMissingPolicyID     = errors.New("missing policy id")
	ErrInvalidPolicyIDType = errors.New("invalid policy id type")
	ErrMismatchedPolicyID  = errors.New("mismatched policy ids")
)

func isPolicyMatching(policy map[string]interface{}, signedLayer map[string]interface{}) error {
	policyID, err := getPolicyID(policy)
	if err != nil {
		return err
	}

	signedPolicyID, err := getPolicyID(signedLayer)
	if err != nil {
		return err
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

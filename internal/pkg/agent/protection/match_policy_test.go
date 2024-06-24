// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestIsPolicyMatching(t *testing.T) {
	tests := []struct {
		name                string
		policy, signedLayer map[string]interface{}
		wantErr             error
	}{
		{
			name:    "nil both",
			wantErr: ErrMissingPolicyID,
		},
		{
			name:        "empty both",
			policy:      map[string]interface{}{},
			signedLayer: map[string]interface{}{},
			wantErr:     ErrMissingPolicyID,
		},
		{
			name:   "empty policy",
			policy: map[string]interface{}{},
			signedLayer: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a7",
			},
			wantErr: ErrMissingPolicyID,
		},
		{
			name: "empty signed",
			policy: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a7",
			},
			signedLayer: map[string]interface{}{},
			wantErr:     ErrMissingPolicyID,
		},
		{
			name: "valid match id",
			policy: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a7",
			},
			signedLayer: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a7",
			},
		},
		{
			name: "mismatchmatched id",
			policy: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a7",
			},
			signedLayer: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a8",
			},
			wantErr: ErrMismatchedPolicyID,
		},
		{
			name: "invalid id type",
			policy: map[string]interface{}{
				"id": "681b1230-b798-11ed-8be1-47153ce217a7",
			},
			signedLayer: map[string]interface{}{
				"id": map[string]interface{}{},
			},
			wantErr: ErrInvalidPolicyIDType,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := isPolicyMatching(tc.policy, tc.signedLayer)
			diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

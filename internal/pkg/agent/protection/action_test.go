// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func signPayload(payload []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(payload)

	return ecdsa.SignASN1(rand.Reader, pk, hash[:])
}

func signAction(action map[string]interface{}, emptyData bool, pk *ecdsa.PrivateKey) (map[string]interface{}, error) {
	var (
		payload []byte
		err     error
	)

	if !emptyData {
		payload, err = json.Marshal(action)
		if err != nil {
			return nil, err
		}
	}

	sig, err := signPayload(payload, pk)
	if err != nil {
		return nil, err
	}

	action["signed"] = map[string]interface{}{
		"data":      base64.StdEncoding.EncodeToString(payload),
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
	// Remap the action_id to id same way the fleet server does for checkins
	action["id"] = action["action_id"]
	delete(action, "action_id")
	return action, nil
}

func signActionJSON(actionJSON []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
	var action map[string]interface{}

	err := json.Unmarshal(actionJSON, &action)
	if err != nil {
		return nil, err
	}

	signed, err := signAction(action, false, pk)
	if err != nil {
		return nil, err
	}

	return json.Marshal(signed)
}

func signActionEmptyDataJSON(actionJSON []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
	var action map[string]interface{}

	err := json.Unmarshal(actionJSON, &action)
	if err != nil {
		return nil, err
	}

	signed, err := signAction(action, true, pk)
	if err != nil {
		return nil, err
	}

	return json.Marshal(signed)
}

const testAgentID = "8b09109b-c6c7-4fba-8e11-6c0b6636f985"
const testAction = `{
	"action_id": "2bce6a91-e881-49bd-8a1e-f58bca89c886",
	"expiration": "2023-03-13T15:38:32.446Z",
	"type": "INPUT_ACTION",
	"input_type": "endpoint",
	"data": {
		"command": "isolate",
		"comment": ""
	},
	"@timestamp": "2023-02-27T16:38:32.446Z",
	"agents": [
		` + `"` + testAgentID + `"` + `
	],
	"timeout": 300,
	"user_id": "elastic"
}`

const signThisAction = `{
	"action_id": "b07d53e2-e79f-4b5c-8384-db6d64a47a4e",
	"@timestamp": "2023-03-03T02:19:11.597Z",
	"expiration": "2023-03-03T03:24:11.597Z",
	"type": "INPUT_ACTION",
	"input_type": "osquery",
	"agents": [
	  "5eb767ca-72bb-4296-9d93-a9e17de9054e"
	],
	"user_id": "elastic",
	"data": {
	  "id": "9de96e64-10a1-4146-9e82-0aad63ea3bce",
	  "query": "select * from osquery_info"
	}
  }
  `

func TestSignThisAction(t *testing.T) {
	pk, pubK, err := genKeys()
	if err != nil {
		t.Fatal(err)
	}
	_ = pubK
	actionJSON, err := signActionJSON([]byte(signThisAction), pk)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	err = json.Unmarshal(actionJSON, &m)
	if err != nil {
		t.Fatal(err)
	}

	v := m["signed"]
	if v == nil {
		t.Fatal("unexpected \"signed\" nil")
	}
	signed, ok := v.(map[string]interface{})
	if !ok {
		t.Fatal("unexpected \"signed\" not map[string]interface{}")
	}
	if signed["data"] == nil {
		t.Fatal("unexpected \"signed\" \"data\" nil")
	}
	if signed["signature"] == nil {
		t.Fatal("unexpected \"signed\" \"signature\" nil")
	}
}

func getTestAction(t *testing.T, actionJSON []byte, pk *ecdsa.PrivateKey) fleetapi.ActionApp {
	if !json.Valid(actionJSON) {
		return fleetapi.ActionApp{}
	}

	var err error

	if pk != nil {
		actionJSON, err = signActionJSON(actionJSON, pk)
		if err != nil {
			t.Fatal(err)
		}
	}

	var action fleetapi.ActionApp
	err = json.Unmarshal(actionJSON, &action)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func TestValidateAction(t *testing.T) {
	pk, pubK, err := genKeys()
	if err != nil {
		t.Fatal(err)
	}

	unsignedAction := getTestAction(t, []byte(testAction), nil)
	signedAction := getTestAction(t, []byte(testAction), pk)

	// Action that has valid empty data signed
	signedActionEmptyDataJSON, err := signActionEmptyDataJSON([]byte(testAction), pk)
	if err != nil {
		t.Fatal(err)
	}
	var signedActionEmptyData fleetapi.ActionApp
	err = json.Unmarshal(signedActionEmptyDataJSON, &signedActionEmptyData)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		action     fleetapi.ActionApp
		agentID    string
		wantAction fleetapi.ActionApp
		wantErr    error
	}{
		{
			name:   "empty action",
			action: getTestAction(t, nil, nil),
		},
		{
			name:       "unsigned action",
			action:     unsignedAction,
			wantAction: unsignedAction,
		},
		{
			name:       "signed action, empty agent id",
			action:     signedAction,
			wantAction: signedAction,
			agentID:    "",
			wantErr:    ErrNonMatchingAgentID,
		},
		{
			name:       "signed action, non-matching agent id",
			action:     signedAction,
			wantAction: signedAction,
			agentID:    "ab09109b-c6c7-4fba-8e11-6c0b6636f985",
			wantErr:    ErrNonMatchingAgentID,
		},
		{
			name:       "valid signed action",
			action:     signedAction,
			wantAction: signedAction,
			agentID:    testAgentID,
		},
		{
			name: "signed action corrupted/empty data",
			action: func() fleetapi.ActionApp {
				ac := signedAction
				ac.Signed = &fleetapi.Signed{
					Data:      "",
					Signature: ac.Signed.Signature,
				}
				return ac
			}(),
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "signed empty data action",
			action:  signedActionEmptyData,
			wantErr: ErrInvalidSignedDataValue,
		},
		{
			name: "signed action empty signature",
			action: func() fleetapi.ActionApp {
				ac := signedAction
				ac.Signed = &fleetapi.Signed{
					Data:      ac.Signed.Data,
					Signature: "",
				}
				return ac
			}(),
			wantErr: ErrInvalidSignature,
		},
		{
			name: "signed action invalid base64 data",
			action: func() fleetapi.ActionApp {
				ac := signedAction
				ac.Signed = &fleetapi.Signed{
					Data:      "ABC",
					Signature: ac.Signed.Signature,
				}
				return ac
			}(),
			wantErr: ErrInvalidSignedDataValue,
		},
		{
			name: "signed action invalid base64 signature",
			action: func() fleetapi.ActionApp {
				ac := signedAction
				ac.Signed = &fleetapi.Signed{
					Data:      ac.Signed.Data,
					Signature: "ABC",
				}
				return ac
			}(),
			wantErr: ErrInvalidSignatureValue,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validated, err := ValidateAction(tc.action, pubK, tc.agentID)

			diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}

			if tc.wantErr == nil {
				diff = cmp.Diff(tc.wantAction, validated)
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

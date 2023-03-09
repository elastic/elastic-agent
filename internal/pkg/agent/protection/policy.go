// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/mitchellh/mapstructure"
)

var (
	ErrNotFound = errors.New("not found")
)

// ValidatePolicySignature validates policy document signature, overlays with signed configuration
// returns the policy (with signed data overlaying the original policy), the matching signatureValidationKey
// The signatureValidationKey parameter can be empty, in that case try to read the key from the policy.protected.signing_key
// and validate the signature with that key.
// This would guarantee that the signature validation key returned from the function is the valid key as well.
//
// There could be few cases this function needs to handle:
// 1. The old policy format that doesn't have signature or protected data. Policy should returned without modifications or errors.
// 2. New policy where the signatureValidationKey is nil. No previously known signature validation key, try to read one from the policy, validate and return.
// 3. New policy format with the signatureValidationKey. Validate the signed data normally.
func ValidatePolicySignature(log *logger.Logger, policy map[string]interface{}, signatureValidationKey []byte) (map[string]interface{}, []byte, error) {
	var err error

	log = log.With("context", "Validate policy signature")

	log.Debugf("Passed signature validation key length: %v", len(signatureValidationKey))

	// Try to get the signature validation key from the policy itself if there is no previously known signature validation key
	if len(signatureValidationKey) == 0 {
		signatureValidationKey, err = getPolicySignatureValidationKey(policy)
		log.Debugf("Policy signature validation key length: %v, err: %v", len(signatureValidationKey), err)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		if len(signatureValidationKey) == 0 {
			log.Debug("Signature validation key is not present, skip validation")
			return policy, signatureValidationKey, nil
		}
	}

	// Validate the signature
	// Read protected data and signature from the policy
	data, signature, err := getPolicySignedDataAndSignature(policy)
	log.Debugf("Policy data length: %v, signature length: %v, err: %v", len(data), len(signature), err)
	if err != nil {
		return nil, nil, err
	}

	// Validate signed data
	err = ValidateSignature(data, signature, signatureValidationKey)
	log.Debugf("Policy signature validation result: %v", err)
	if err != nil {
		return nil, nil, err
	}

	if len(data) == 0 {
		log.Debug("Signed data is empty, skip policy overlay")
		return policy, signatureValidationKey, nil
	}

	// Unmarshal signed layer of the policy
	var signedLayer map[string]interface{}
	err = json.Unmarshal(data, &signedLayer)
	if err != nil {
		return nil, nil, err
	}

	// Check if the signed layer has the same id as the policy
	if err := isPolicyMatching(policy, signedLayer); err != nil {
		return nil, nil, err
	}

	// Overlay signed layer onto the policy
	policy = overlayPolicy(policy, signedLayer)

	// Read the key from the policy after it was overlayed with signed data
	// Coding for the key that could potentially change in the future
	svk, err := getPolicySignatureValidationKey(policy)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}
	signatureValidationKey = svk

	return policy, signatureValidationKey, nil
}

func GetAgentProtection(policy map[string]interface{}) map[string]interface{} {
	v, ok := policy["agent"]
	if !ok {
		return nil
	}

	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}

	v, ok = m["protection"]
	if !ok {
		return nil
	}

	m, ok = v.(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}

func GetAgentProtectionConfig(policy map[string]interface{}) (cfg Config, err error) {
	m := GetAgentProtection(policy)
	if m == nil {
		return cfg, ErrNotFound
	}

	var cfgSer configDeserializer
	err = mapstructure.Decode(m, &cfgSer)
	if err != nil {
		return cfg, err
	}

	var signingKey []byte
	if cfgSer.SigningKey != "" {
		signingKey, err = base64.StdEncoding.DecodeString(cfgSer.SigningKey)
		if err != nil {
			return cfg, err
		}
	}

	return Config{
		Enabled:                cfgSer.Enabled,
		UninstallTokenHash:     cfgSer.UninstallTokenHash,
		SignatureValidationKey: signingKey,
	}, nil
}

// getPolicySigningKey returns the signing key from the policy configuration
func getPolicySignatureValidationKey(policy map[string]interface{}) ([]byte, error) {
	cfg, err := GetAgentProtectionConfig(policy)
	if err != nil {
		return nil, err
	}
	return cfg.SignatureValidationKey, nil
}

func getPolicySignedDataAndSignature(policy map[string]interface{}) (data, signature []byte, err error) {
	v, ok := policy["signed"]
	if !ok {
		return data, signature, ErrNotFound
	}
	signed, ok := v.(map[string]interface{})
	if !ok {
		return data, signature, ErrNotFound
	}

	data, err = getBytes(signed, "data")
	if err != nil {
		return
	}

	signature, err = getBytes(signed, "signature")
	if err != nil {
		return
	}

	return data, signature, err
}

func getBytes(m map[string]interface{}, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, ErrNotFound
	}

	s, ok := v.(string)
	if !ok {
		return nil, ErrNotFound
	}

	val, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed decoding %v value: %w", key, err)
	}
	return val, nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrInvalidSignatureValidationKey     = errors.New("invalid signature validation key")
	ErrUnsupportedSignatureValidationKey = errors.New("unsupported signature validation key")
	ErrInvalidSignature                  = errors.New("invalid signature")
)

// ValidateSignature validates the data signature against the signatureValidationKey
func ValidateSignature(data, signature, signatureValidationKey []byte) error {
	pk, err := x509.ParsePKIXPublicKey(signatureValidationKey)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return fmt.Errorf("%w: %v", ErrInvalidSignatureValidationKey, err)
	}

	pubKey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedSignatureValidationKey
	}

	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)
	if !valid {
		return ErrInvalidSignature
	}
	return nil
}

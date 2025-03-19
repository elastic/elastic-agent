// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
)

func getCipherAEAD(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCMWithRandomNonce(block)
}

// Encrypt encrypts the data with AES-GCM
func Encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	// The first parameter is nonce in order to get the ciphertext as concatenation of nonce and encrypted data
	ciphertext := aesGCM.Seal(nil, nil, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts the data with AES-GCM
func Decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return aesGCM.Open(nil, nil, data, nil)
}

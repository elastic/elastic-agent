// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"syscall"
)

// AESKeyType indicates the AES key length.
type AESKeyType int

const (
	// AES128 represents a 128 bit key length
	AES128 AESKeyType = 16
	// AES192 represents a 192 bit key length
	AES192 AESKeyType = 24
	// AES256 represents a 256 bit key length
	AES256 AESKeyType = 32
)

// String returns the AES key length as a string.
func (kt AESKeyType) String() string {
	switch kt {
	case AES128:
		return "AES128"
	case AES192:
		return "AES192"
	case AES256:
		return "AES256"
	}
	return ""
}

// NewKey generates new AES key as bytes
func NewKey(kt AESKeyType) ([]byte, error) {
	key := make([]byte, kt)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// NewKeyHexString generates new AES key as hex encoded string
func NewKeyHexString(kt AESKeyType) (string, error) {
	key, err := NewKey(kt)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Encrypt encrypts the data with AES-GCM
func Encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	// The first parameter is nonce in order to get the ciphertext as concatenation of nonce and encrypted data
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

// EncryptHex encrypts with hex string key, producing hex encoded result
func EncryptHex(key string, data []byte) (string, error) {
	bkey, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	enc, err := Encrypt(bkey, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

// Decrypt decrypts the data with AES-GCM
func Decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, syscall.EINVAL
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// DecryptHex decrypts with hex string key and data
func DecryptHex(key string, data string) ([]byte, error) {
	bkey, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	bdata, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(bkey, bdata)
}

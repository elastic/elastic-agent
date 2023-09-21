// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package aesgcm

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var testKeyTypes []AESKeyType = []AESKeyType{AES128, AES192, AES256}

func TestNewKey(t *testing.T) {
	for _, kt := range testKeyTypes {
		b, err := NewKey(kt)
		if err != nil {
			t.Error(err)
		}

		diff := cmp.Diff(int(kt), len(b))
		if diff != "" {
			t.Error(diff)
		}
	}
}

func TestNewKeyHexString(t *testing.T) {
	for _, kt := range testKeyTypes {
		s, err := NewKeyHexString(kt)
		if err != nil {
			t.Error(err)
		}

		diff := cmp.Diff(int(kt)*2, len(s))
		if diff != "" {
			t.Error(diff)
		}
	}

}

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "nil",
		},
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "foobar",
			data: []byte("foobar"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, kt := range testKeyTypes {
				t.Run(kt.String(), func(t *testing.T) {
					key, err := NewKey(kt)
					if err != nil {
						t.Error(err)
					}
					enc, err := Encrypt(key, tc.data)
					if err != nil {
						t.Error(err)
					}
					dec, err := Decrypt(key, enc)
					if err != nil {
						t.Error(err)
					}

					if len(tc.data) == 0 {
						diff := cmp.Diff(len(tc.data), len(dec))
						if diff != "" {
							t.Error(diff)
						}
					} else {
						diff := cmp.Diff(tc.data, dec)
						if diff != "" {
							t.Error(diff)
						}
					}
				})
			}
		})
	}

}

func TestEncryptDecryptDifferentLengths(t *testing.T) {
	const maxDataSize = 55 // test for sufficient length for the key and a bit more
	for _, kt := range testKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			key, err := NewKey(kt)
			if err != nil {
				t.Error(err)
			}
			for i := 0; i < maxDataSize; i++ {
				data := make([]byte, i)
				_, err := rand.Read(data)
				if err != nil {
					t.Fatal(err)
				}
				name := strconv.Itoa(i)
				t.Run(name, func(t *testing.T) {
					enc, err := Encrypt(key, data)
					if err != nil {
						t.Error(err)
					}
					dec, err := Decrypt(key, enc)
					if err != nil {
						t.Error(err)
					}

					if len(data) == 0 {
						diff := cmp.Diff(len(data), len(dec))
						if diff != "" {
							t.Error(diff)
						}
					} else {
						diff := cmp.Diff(data, dec)
						if diff != "" {
							t.Error(diff)
						}
					}
				})
			}
		})
	}
}

func TestEncryptDecryptHex(t *testing.T) {
	aes256Key, err := NewKeyHexString(AES256)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		key  string
		data []byte
		err  error
	}{
		{
			name: "emptykey",
			key:  "",
			err:  aes.KeySizeError(0),
		},
		{
			name: "nonhexkey",
			key:  "123",
			err:  hex.ErrLength,
		},
		{
			name: "foobar",
			key:  aes256Key,
			data: []byte("foobar"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := EncryptHex(tc.key, tc.data)
			if !errors.Is(tc.err, err) {
				t.Fatalf(cmp.Diff(tc.err, err))
			}

			dec, err := DecryptHex(tc.key, enc)
			if !errors.Is(tc.err, err) {
				t.Fatalf(cmp.Diff(tc.err, err))
			}

			if len(tc.data) == 0 {
				diff := cmp.Diff(len(tc.data), len(dec))
				if diff != "" {
					t.Error(diff)
				}
			} else {
				diff := cmp.Diff(tc.data, dec)
				if diff != "" {
					t.Error(diff)
				}
			}
		})
	}

}

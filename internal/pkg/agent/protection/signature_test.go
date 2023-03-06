// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
)

func decodeBase64(t *testing.T, sb64 string) []byte {
	b, err := base64.StdEncoding.DecodeString(sb64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const testPayload = `{"id":"4d7d84e0-b46d-11ed-ba3a-57052bcc437f","agent":{"protection":{"enabled":true,"uninstall_token_hash":"","signing_key":"MF7X/qVFlNjHhuBIp+7/AGA=="}}}`

func genKeys() (pk *ecdsa.PrivateKey, pubK []byte, err error) {
	pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	pubK, err = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	return pk, pubK, err
}

func sign(data []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, pk, hash[:])
}

func genRSAKeys() (pk *rsa.PrivateKey, pubK []byte, err error) {
	pk, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	pubK, err = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	return pk, pubK, err
}

func signRSA(data []byte, pk *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPSS(rand.Reader, pk, crypto.SHA256, hash[:], nil)
}

func TestValidateSignatureBase64(t *testing.T) {
	data := []byte(testPayload)

	pk, signatureValidationKey, err := genKeys()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := sign(data, pk)
	if err != nil {
		t.Fatal(err)
	}

	rsaPK, rsaSignatureValidationKey, err := genRSAKeys()
	if err != nil {
		t.Fatal(err)
	}
	signatureRSA, err := signRSA(data, rsaPK)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                   string
		data                   string
		signature              string
		signatureValidationKey string
		wantErr                error
	}{
		{
			name:                   "valid signature",
			data:                   base64.StdEncoding.EncodeToString(data),
			signature:              base64.StdEncoding.EncodeToString(signature),
			signatureValidationKey: base64.StdEncoding.EncodeToString(signatureValidationKey),
		},
		{
			name:                   "usupported signature key",
			data:                   base64.StdEncoding.EncodeToString(data),
			signature:              base64.StdEncoding.EncodeToString(signatureRSA),
			signatureValidationKey: base64.StdEncoding.EncodeToString(rsaSignatureValidationKey),
			wantErr:                ErrUnsupportedSignatureValidationKey,
		},
		{
			name:                   "corrupted signature key",
			data:                   base64.StdEncoding.EncodeToString(data),
			signature:              base64.StdEncoding.EncodeToString(signature),
			signatureValidationKey: "AAAA" + base64.StdEncoding.EncodeToString(signatureValidationKey),
			wantErr:                ErrInvalidSignatureValidationKey,
		},
		{
			name:                   "invalid signature",
			data:                   base64.StdEncoding.EncodeToString(data),
			signature:              "AAAA" + base64.StdEncoding.EncodeToString(signature),
			signatureValidationKey: base64.StdEncoding.EncodeToString(signatureValidationKey),
			wantErr:                ErrInvalidSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSignature(decodeBase64(t, tc.data), decodeBase64(t, tc.signature), decodeBase64(t, tc.signatureValidationKey))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error got: %v, want: %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateJoeySignature(t *testing.T) {
	const signingKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBfgV9TI5KmWI8gkM9hX1Y2upAke+z8BtCsZYYHcGcWgLfOcIC37dLkGVOqUojKEkbB3WV/3Sa+DyBODLEa3Gbw=="
	const data = `eyJhY3Rpb25faWQiOiIyYmNlNmE5MS1lODgxLTQ5YmQtOGExZS1mNThiY2E4OWM4ODYiLCJleHBpcmF0aW9uIjoiMjAyMy0wMy0xM1QxNTozODozMi40NDZaIiwidHlwZSI6IklOUFVUX0FDVElPTiIsImlucHV0X3R5cGUiOiJlbmRwb2ludCIsImRhdGEiOnsiY29tbWFuZCI6Imlzb2xhdGUiLCJjb21tZW50IjoiIn0sIkB0aW1lc3RhbXAiOiIyMDIzLTAyLTI3VDE2OjM4OjMyLjQ0NloiLCJhZ2VudHMiOlsiOGIwOTEwOWItYzZjNy00ZmJhLThlMTEtNmMwYjY2MzZmOTg1Il0sInRpbWVvdXQiOjMwMCwidXNlcl9pZCI6ImVsYXN0aWMifQ==`
	const signature = `MEUCIDzGWwIVYqXNq7EGwrN1u0lr67JZrYI+kb6CIsP7NavCAiEA5Lywcwty2WBfKAaBn6x+9tMXgqhil+82ud2Z/pzb8GQ=`

	err := ValidateSignature(decodeBase64(t, data), decodeBase64(t, signature), decodeBase64(t, signingKey))

	if err != nil {
		t.Fatal(err)
	}
}

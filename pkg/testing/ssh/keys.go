package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
)

// NewPrivateKey creates RSA private key
func NewPrivateKey() (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2056)
	if err != nil {
		return nil, err
	}
	err = pk.Validate()
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// EncodeToPEM encodes private key to PEM format
func EncodeToPEM(privateKey *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   der,
	}
	return pem.EncodeToMemory(&privBlock)
}

// NewPublicKey returns bytes for writing to .pub file
func NewPublicKey(pk *rsa.PublicKey) ([]byte, error) {
	pub, err := ssh.NewPublicKey(pk)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(pub), nil
}

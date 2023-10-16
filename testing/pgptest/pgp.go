// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package pgptest

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Sing signs data using RSA. It creates the key, sings data and returns the
// ASCII armored public key and detached signature.
func Sing(t *testing.T, data io.Reader) ([]byte, []byte) {
	pub := &bytes.Buffer{}
	asc := &bytes.Buffer{}

	// Create a new key. The openpgp.Entity hold the private and public keys.
	entity, err := openpgp.NewEntity("somekey", "", "", nil)
	require.NoError(t, err, "could not create PGP key")

	// Create an encoder to serialize the public key.
	wPubKey, err := armor.Encode(pub, openpgp.PublicKeyType, nil)
	require.NoError(t, err, "could not create PGP ASCII Armor encoder")

	// Writes the public key to the io.Writer padded to armor.Encode.
	// Use entity.SerializePrivate if you need the private key.
	err = entity.Serialize(wPubKey)
	require.NoError(t, err, "could not serialize the public key")
	// cannot use defer as it needs to be closed before pub.Bytes() is invoked.
	wPubKey.Close()

	err = openpgp.ArmoredDetachSign(asc, entity, data, nil)
	require.NoError(t, err, "failed signing the data")

	return pub.Bytes(), asc.Bytes()
}

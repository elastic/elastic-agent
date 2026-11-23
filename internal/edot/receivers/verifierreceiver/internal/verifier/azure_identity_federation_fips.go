// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// azureIdentityFederationSupported reports whether Azure credentials (identity
// federation and default credentials) are compiled into this build.
const azureIdentityFederationSupported = false

// The Azure credential helpers are unavailable in FIPS builds: the beats Azure
// identity federation package is excluded from them because azidentity
// transitively imports golang.org/x/crypto/pkcs12 (RC2/DES), so azidentity must
// not be linked either.
func newAzureIdentityFederationCredential(AzureAuthConfig, azcore.ClientOptions) (azcore.TokenCredential, error) {
	return nil, errors.New("Azure identity federation is not supported in FIPS builds")
}

func newAzureDefaultCredential(azcore.ClientOptions) (azcore.TokenCredential, error) {
	return nil, errors.New("Azure default credentials are not supported in FIPS builds")
}

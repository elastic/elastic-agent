// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// azureIdentityFederationSupported reports whether Azure identity federation is
// compiled into this build.
const azureIdentityFederationSupported = false

// newAzureIdentityFederationCredential is unavailable in FIPS builds: the
// beats Azure identity federation package is excluded from them because the
// Azure SDK transitively imports golang.org/x/crypto/pkcs12 (RC2/DES).
func newAzureIdentityFederationCredential(AzureAuthConfig, azcore.ClientOptions) (azcore.TokenCredential, error) {
	return nil, errors.New("Azure identity federation is not supported in FIPS builds")
}

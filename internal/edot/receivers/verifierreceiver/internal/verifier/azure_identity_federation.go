// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/elastic/beats/v7/x-pack/libbeat/common/identityfederation"
)

// azureIdentityFederationSupported reports whether Azure identity federation is
// compiled into this build.
const azureIdentityFederationSupported = true

// newAzureIdentityFederationCredential builds the OIDC client-assertion
// credential using the shared Identity Federation package from beats.
func newAzureIdentityFederationCredential(authConfig AzureAuthConfig, clientOpts azcore.ClientOptions) (azcore.TokenCredential, error) {
	return identityfederation.AzureNewClientAssertionCredential(identityfederation.AzureParams{
		TenantID:    authConfig.TenantID,
		ClientID:    authConfig.ClientID,
		JWTFilePath: authConfig.IDTokenFile,
		Options:     &azidentity.ClientAssertionCredentialOptions{ClientOptions: clientOpts},
	})
}

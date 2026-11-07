// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:generate mdatagen metadata.yaml

// Package awsidentityfederationextension resolves AWS credentials for the Identity
// Federation flow of Elastic managed integrations: it fetches a JWT from the Elastic
// workload-identity-issuer over mTLS and assumes the customer's IAM role with
// sts:AssumeRoleWithWebIdentity, reusing the libbeat identityfederation implementation.
// AWS-SDK-based components consume the credentials through their credentials_provider
// option, like the awscredentialsprovider extension.
package awsidentityfederationextension // import "github.com/elastic/elastic-agent/internal/edot/extensions/awsidentityfederationextension"

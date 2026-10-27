// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:generate mdatagen metadata.yaml

// Package awsidentityfederationextension provides AWS credentials for the
// Identity Federation flow of Elastic managed integrations (agentless).
//
// The extension fetches a short-lived JWT from the Elastic workload-identity-issuer
// over mTLS and exchanges it for AWS credentials with sts:AssumeRoleWithWebIdentity
// against the customer's IAM role. AWS-SDK-based components such as the
// awscloudwatch receiver consume the resolved credentials through their
// credentials_provider option, exactly like the awscredentialsprovider extension.
//
// The token exchange is implemented by the shared libbeat identityfederation
// package, so the OTel and Beats inputs share one implementation of the
// workload-identity flow.
package awsidentityfederationextension // import "github.com/elastic/elastic-agent/internal/edot/extensions/awsidentityfederationextension"

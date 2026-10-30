// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package awsidentityfederationextension // import "github.com/elastic/elastic-agent/internal/edot/extensions/awsidentityfederationextension"

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"

	"github.com/elastic/beats/v7/x-pack/libbeat/common/identityfederation"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	// stsAudience is the audience the customer's role trust policy pins ("<issuer>:aud").
	stsAudience = "sts.amazonaws.com"
	// defaultSTSRegion mirrors the fallback of the Beats AWS inputs.
	defaultSTSRegion = "us-east-1"
)

// Provider is the interface AWS-SDK-based components use to obtain credentials from
// this extension; the awscloudwatch receiver declares a structurally identical one.
type Provider interface {
	// GetCredentialsProvider returns the credentials provider resolved by the
	// extension. It is only valid after the extension has been started.
	GetCredentialsProvider() aws.CredentialsProvider
}

type awsIdentityFederationExtension struct {
	cfg    *Config
	logger *zap.Logger
	creds  aws.CredentialsProvider
}

var (
	_ extension.Extension = (*awsIdentityFederationExtension)(nil)
	_ Provider            = (*awsIdentityFederationExtension)(nil)
)

func newExtension(cfg *Config, logger *zap.Logger) *awsIdentityFederationExtension {
	return &awsIdentityFederationExtension{cfg: cfg, logger: logger}
}

// Start wires the credential chain (issuer JWT over mTLS → AssumeRoleWithWebIdentity →
// cached session). Nothing is fetched here: the first credential retrieval performs the
// exchange, so a misconfigured role surfaces on the consuming component.
func (e *awsIdentityFederationExtension) Start(ctx context.Context, _ component.Host) error {
	issuer, err := e.cfg.resolveIssuerSettings()
	if err != nil {
		return err
	}

	beatsLogger, err := logp.NewZapLogger(e.logger)
	if err != nil {
		return fmt.Errorf("wrapping the collector logger: %w", err)
	}
	tokenSource, err := identityfederation.NewWIITokenSource(issuer.issuerURL, issuer.certFile, issuer.keyFile, stsAudience, beatsLogger)
	if err != nil {
		return fmt.Errorf("configuring the workload-identity token source: %w", err)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading the AWS SDK configuration: %w", err)
	}
	switch {
	case e.cfg.STSRegion != "":
		awsCfg.Region = e.cfg.STSRegion
	case awsCfg.Region == "":
		awsCfg.Region = defaultSTSRegion
	}

	step := &identityfederation.AWSWIIWebIdentityStep{
		RoleARN:     e.cfg.RoleARN,
		TokenSource: tokenSource,
		Options: func(o *stscreds.WebIdentityRoleOptions) {
			if e.cfg.SessionName != "" {
				o.RoleSessionName = e.cfg.SessionName
			}
			if e.cfg.Duration > 0 {
				o.Duration = e.cfg.Duration
			}
		},
	}
	e.creds = step.BuildCredentialsCache(sts.NewFromConfig(awsCfg))

	e.logger.Info("Resolving AWS credentials through Identity Federation (workload-identity-issuer)",
		zap.String("role_arn", e.cfg.RoleARN),
		zap.String("issuer_url", issuer.issuerURL),
		zap.String("sts_region", awsCfg.Region),
	)
	return nil
}

func (e *awsIdentityFederationExtension) Shutdown(context.Context) error {
	return nil
}

// GetCredentialsProvider implements Provider.
func (e *awsIdentityFederationExtension) GetCredentialsProvider() aws.CredentialsProvider {
	return e.creds
}

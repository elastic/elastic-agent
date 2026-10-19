// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/pkg/testing/common"
)

const ProvisionerExternal = "external"

type ExternalProvisioner struct {
	logger common.Logger
	stack  common.Stack
}

// NewExternalProvisioner creates a stack provisioner backed by environment variables.
func NewExternalProvisioner() (common.StackProvisioner, error) {
	stack := common.Stack{
		Provisioner:   ProvisionerExternal,
		Elasticsearch: os.Getenv("ELASTICSEARCH_HOST"),
		Kibana:        os.Getenv("KIBANA_HOST"),
		Username:      os.Getenv("ELASTICSEARCH_USERNAME"),
		Password:      os.Getenv("ELASTICSEARCH_PASSWORD"),
		Ready:         true,
	}
	if stack.Elasticsearch == "" {
		return nil, fmt.Errorf("the %q stack provisioner requires ELASTICSEARCH_HOST to be set", ProvisionerExternal)
	}
	if stack.Kibana == "" {
		return nil, fmt.Errorf("the %q stack provisioner requires KIBANA_HOST to be set", ProvisionerExternal)
	}
	return &ExternalProvisioner{stack: stack}, nil
}

func (p *ExternalProvisioner) Name() string {
	return ProvisionerExternal
}

func (p *ExternalProvisioner) Location() common.ProvisionerLocation {
	return common.ProvisionerLocationRemote
}

func (p *ExternalProvisioner) SetLogger(l common.Logger) {
	p.logger = l
}

// Create returns the Stack that the environment variables describe. No remote
// provisioning is performed, the stack is considered immediately ready.
func (p *ExternalProvisioner) Create(_ context.Context, req common.StackRequest) (common.Stack, error) {
	stack := p.stack
	stack.ID = req.ID
	stack.Version = req.Version
	return stack, nil
}

// WaitForReady is a no-op, the external stack is assumed to be ready.
func (p *ExternalProvisioner) WaitForReady(_ context.Context, stack common.Stack) (common.Stack, error) {
	return stack, nil
}

// Delete is a no-op, the external stack is managed outside of the test runner.
func (p *ExternalProvisioner) Delete(_ context.Context, _ common.Stack) error {
	return nil
}

// Upgrade is not supported for an external stack.
func (p *ExternalProvisioner) Upgrade(_ context.Context, _ common.Stack, _ string) error {
	return fmt.Errorf("upgrade is not supported for the %q stack provisioner", ProvisionerExternal)
}

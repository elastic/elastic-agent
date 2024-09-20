// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package null

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

const (
	Name = "null"
)

type instanceProvisioner struct {
	logger runner.Logger
}

// NewInstanceProvisioner creates the null provisioner
func NewInstanceProvisioner() runner.InstanceProvisioner {
	return &instanceProvisioner{}
}

func (p *instanceProvisioner) Name() string {
	return Name
}

func (p *instanceProvisioner) SetLogger(l runner.Logger) {
	p.logger = l
}

func (p *instanceProvisioner) Type() runner.ProvisionerType {
	return runner.ProvisionerTypeVM
}

func (p *instanceProvisioner) Supported(os define.OS) bool {
	return true
}

func (p *instanceProvisioner) Provision(ctx context.Context, cfg runner.Config, batches []runner.OSBatch) ([]runner.Instance, error) {
	return nil, fmt.Errorf("null provisioner cannot provision")
}

func (p *instanceProvisioner) Clean(ctx context.Context, _ runner.Config, instances []runner.Instance) error {
	// nothing to clean
	return nil
}

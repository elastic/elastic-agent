// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package local provides a common.InstanceProvisioner and common.OSRunner
// that run tests directly on the host running mage, instead of provisioning
// a VM or Kubernetes cluster.
package local

import (
	"context"
	"runtime"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// Name is the name of the local instance provisioner.
const Name = "local"

// NewProvisioner creates a new local instance provisioner.
func NewProvisioner() common.InstanceProvisioner {
	return &provisioner{}
}

type provisioner struct {
	logger common.Logger
}

func (p *provisioner) Name() string {
	return Name
}

func (p *provisioner) Type() common.ProvisionerType {
	return common.ProvisionerTypeLocal
}

func (p *provisioner) SetLogger(l common.Logger) {
	p.logger = l
}

// Supported only allows batches matching the current host's OS and architecture.
func (p *provisioner) Supported(os define.OS) bool {
	return os.Type == runtime.GOOS && os.Arch == runtime.GOARCH
}

// Provision returns one instance per batch, representing the current host; no
// actual instance is created.
func (p *provisioner) Provision(_ context.Context, _ common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	instances := make([]common.Instance, 0, len(batches))
	for _, batch := range batches {
		instances = append(instances, common.Instance{
			ID:          batch.ID,
			Name:        "local",
			Provisioner: Name,
		})
	}
	return instances, nil
}

// Clean does nothing, there is nothing to clean up for the local host.
func (p *provisioner) Clean(_ context.Context, _ common.Config, _ []common.Instance) error {
	return nil
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

type ProvisionerType uint32

const (
	ProvisionerTypeVM ProvisionerType = iota
	ProvisionerTypeK8SCluster
	ProvisionerTypeLocal
)

// ProvisionerLocation describes whether a provisioner's resources run in the
// local development environment or in remote infrastructure.
type ProvisionerLocation uint32

const (
	ProvisionerLocationRemote ProvisionerLocation = iota
	ProvisionerLocationLocal
)

// Instance represents a provisioned instance.
type Instance struct {
	// Provider is the instance provider for the instance.
	// See INSTANCE_PROVISIONER environment variable for the supported providers.
	Provider string `yaml:"provider"`
	// ID is the identifier of the instance.
	//
	// This must be the same ID of the OSBatch.
	ID string `yaml:"id"`
	// Name is the nice-name of the instance.
	Name string `yaml:"name"`
	// Provisioner is the instance provider for the instance.
	// See INSTANCE_PROVISIONER environment variable for the supported Provisioner.
	Provisioner string `yaml:"provisioner"`
	// IP is the IP address of the instance.
	IP string `yaml:"ip"`
	// Username is the username used to SSH to the instance.
	Username string `yaml:"username"`
	// RemotePath is the based path used for performing work on the instance.
	RemotePath string `yaml:"remote_path"`
	// Prepared indicates the instance is already prepared for running tests
	// (e.g. the build toolchain is baked into the image), so the runner can
	// skip the Prepare step. Provisioners that ship a ready-to-use image set
	// this to true.
	Prepared bool `yaml:"prepared"`
	// Internal holds internal information used by the provisioner.
	// Best to not touch the contents of this, and leave it be for
	// the provisioner.
	Internal map[string]interface{} `yaml:"internal"`
}

// InstanceProvisioner performs the provisioning of instances.
type InstanceProvisioner interface {
	// Name returns the name of the instance provisioner.
	Name() string

	// Type returns the type of the provisioner.
	Type() ProvisionerType

	// Location returns whether the provisioned instances run locally or remotely.
	Location() ProvisionerLocation

	// SetLogger sets the logger for it to use.
	SetLogger(l Logger)

	// Supported returns true of false if the provisioner supports the given batch.
	Supported(batch define.OS) bool

	// Provision brings up the machines.
	//
	// The provision should re-use already prepared instances when possible.
	Provision(ctx context.Context, cfg Config, batches []OSBatch) ([]Instance, error)

	// Clean cleans up all provisioned resources.
	Clean(ctx context.Context, cfg Config, instances []Instance) error
}

// InstanceNetworkAttacher is an optional interface an InstanceProvisioner may
// implement to attach a provisioned instance to an additional, externally-managed
// network so it can reach a stack that lives on that network.
//
// It is used by the local stack provisioner together with the docker instance
// provisioner: the local stack runs as a set of containers on its own compose
// network, and the test container must join that network to resolve the stack's
// services by name (so TLS hostnames match). The runner calls this when the stack
// advertises a network and the instance provisioner implements this interface;
// otherwise it is a no-op.
type InstanceNetworkAttacher interface {
	// AttachInstanceToNetwork attaches the given instance to the named network.
	// It must be idempotent (attaching an already-attached instance is not an error).
	AttachInstanceToNetwork(ctx context.Context, instance Instance, network string) error
}

// LocalStackCompatible is implemented by local instance provisioners that can
// reach a local stack. Locality alone is not sufficient: for example, a VM or a
// Kubernetes cluster running locally still needs an explicit networking bridge.
type LocalStackCompatible interface {
	SupportsLocalStack() bool
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/testing/define"
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
	// Internal holds internal information used by the provisioner.
	// Best to not touch the contents of this, and leave it be for
	// the provisioner.
	Internal map[string]interface{} `yaml:"internal"`
}

// InstanceProvisioner performs the provisioning of instances.
type InstanceProvisioner interface {
	// Name returns the name of the instance provisioner.
	Name() string

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

// Stack is a created stack.
type Stack struct {
	// ID is the identifier of the instance.
	//
	// This must be the same ID used for requesting a stack.
	ID string `yaml:"id"`

	// Provisioner is the stack provisioner. See STACK_PROVISIONER environment
	// variable for the supported provisioners.
	Provisioner string `yaml:"provisioner"`

	// Version is the version of the stack.
	Version string `yaml:"version"`

	// Ready determines if the stack is ready to be used.
	Ready bool `yaml:"ready"`

	// Elasticsearch is the URL to communicate with elasticsearch.
	Elasticsearch string `yaml:"elasticsearch"`

	// Kibana is the URL to communication with kibana.
	Kibana string `yaml:"kibana"`

	// Username is the username.
	Username string `yaml:"username"`

	// Password is the password.
	Password string `yaml:"password"`

	// Internal holds internal information used by the provisioner.
	// Best to not touch the contents of this, and leave it be for
	// the provisioner.
	Internal map[string]interface{} `yaml:"internal"`
}

// StackRequest request for a new stack.
type StackRequest struct {
	// ID is the unique ID for the stack.
	ID string `yaml:"id"`

	// Version is the version of the stack.
	Version string `yaml:"version"`
}

// StackProvisioner performs the provisioning of stacks.
type StackProvisioner interface {
	// Name returns the name of the stack provisioner.
	Name() string

	// SetLogger sets the logger for it to use.
	SetLogger(l Logger)

	// Create creates a stack.
	Create(ctx context.Context, request StackRequest) (Stack, error)

	// WaitForReady should block until the stack is ready or the context is cancelled.
	WaitForReady(ctx context.Context, stack Stack) (Stack, error)

	// Delete deletes the stack.
	Delete(ctx context.Context, stack Stack) error
}

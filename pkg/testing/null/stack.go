// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package null

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

type stackProvisioner struct {
	log runner.Logger
}

// NewStackProvisioner creates a new null stack provisioner
func NewStackProvisioner() runner.StackProvisioner {
	return &stackProvisioner{}
}

func (prov *stackProvisioner) Name() string {
	return Name
}

func (prov *stackProvisioner) SetLogger(l runner.Logger) {
	prov.log = l
}

func (prov *stackProvisioner) Create(ctx context.Context, request runner.StackRequest) (runner.Stack, error) {
	return runner.Stack{}, fmt.Errorf("null provisioner cannot provision")
}

func (prov *stackProvisioner) WaitForReady(ctx context.Context, stack runner.Stack) (runner.Stack, error) {
	// nothing to wait for
	return runner.Stack{}, nil
}

func (prov *stackProvisioner) Delete(ctx context.Context, stack runner.Stack) error {
	// nothing to delete
	return nil
}

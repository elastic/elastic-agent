// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

// ProvisionerConfig is the configuration for the ESS provisioner.
type ProvisionerConfig struct {
	Identifier string
	APIKey     string
	Region     string
}

// Validate returns an error if the information is invalid.
func (c *ProvisionerConfig) Validate() error {
	if c.Identifier == "" {
		return errors.New("field Identifier must be set")
	}
	if c.APIKey == "" {
		return errors.New("field APIKey must be set")
	}
	if c.Region == "" {
		return errors.New("field Region must be set")
	}
	return nil
}

type provisioner struct {
	logger runner.Logger
	cfg    ProvisionerConfig
	client *Client
}

// NewProvisioner creates the ESS provisioner
func NewProvisioner(cfg ProvisionerConfig) (runner.StackProvisioner, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	essClient := NewClient(Config{
		ApiKey: cfg.APIKey,
	})
	return &provisioner{
		cfg:    cfg,
		client: essClient,
	}, nil
}

func (p *provisioner) SetLogger(l runner.Logger) {
	p.logger = l
}

// Create creates a stack.
func (p *provisioner) Create(ctx context.Context, request runner.StackRequest) (runner.Stack, error) {
	// allow up to 2 minutes for request
	createCtx, createCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer createCancel()
	resp, err := p.createDeployment(createCtx, request,
		map[string]string{
			"division":          "engineering",
			"org":               "ingest",
			"team":              "elastic-agent",
			"project":           "elastic-agent",
			"integration-tests": "true",
		})
	if err != nil {
		return runner.Stack{}, err
	}
	return runner.Stack{
		ID:            request.ID,
		Version:       request.Version,
		Elasticsearch: resp.ElasticsearchEndpoint,
		Kibana:        resp.KibanaEndpoint,
		Username:      resp.Username,
		Password:      resp.Password,
		Internal: map[string]interface{}{
			"deployment_id": resp.ID,
		},
		Ready: false,
	}, nil
}

// WaitForReady should block until the stack is ready or the context is cancelled.
func (p *provisioner) WaitForReady(ctx context.Context, stack runner.Stack) (runner.Stack, error) {
	deploymentID, err := p.getDeploymentID(stack)
	if err != nil {
		return stack, fmt.Errorf("failed to get deployment ID from the stack: %w", err)
	}
	// allow up to 10 minutes for it to become ready
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	p.logger.Logf("Waiting for cloud stack %s to be ready [stack_id: %s, deployment_id: %s]", stack.Version, stack.ID, deploymentID)
	ready, err := p.client.DeploymentIsReady(ctx, deploymentID, 30*time.Second)
	if err != nil {
		return stack, fmt.Errorf("failed to check for cloud %s [stack_id: %s, deployment_id: %s] to be ready: %w", stack.Version, stack.ID, deploymentID, err)
	}
	if !ready {
		return stack, fmt.Errorf("cloud %s [stack_id: %s, deployment_id: %s] never became ready: %w", stack.Version, stack.ID, deploymentID, err)
	}
	stack.Ready = true
	return stack, nil
}

// Delete deletes a stack.
func (p *provisioner) Delete(ctx context.Context, stack runner.Stack) error {
	deploymentID, err := p.getDeploymentID(stack)
	if err != nil {
		return err
	}

	// allow up to 1 minute for request
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	p.logger.Logf("Destroying cloud stack %s [stack_id: %s, deployment_id: %s]", stack.Version, stack.ID, deploymentID)
	return p.client.ShutdownDeployment(ctx, deploymentID)
}

func (p *provisioner) createDeployment(ctx context.Context, r runner.StackRequest, tags map[string]string) (*CreateDeploymentResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	p.logger.Logf("Creating cloud stack %s [stack_id: %s]", r.Version, r.ID)
	name := fmt.Sprintf("%s-%s", strings.Replace(p.cfg.Identifier, ".", "-", -1), r.ID)

	// prepare tags
	tagArray := make([]Tag, 0, len(tags))
	for k, v := range tags {
		tagArray = append(tagArray, Tag{
			Key:   k,
			Value: v,
		})
	}

	createDeploymentRequest := CreateDeploymentRequest{
		Name:    name,
		Region:  p.cfg.Region,
		Version: r.Version,
		Tags:    tagArray,
	}

	resp, err := p.client.CreateDeployment(ctx, createDeploymentRequest)
	if err != nil {
		p.logger.Logf("Failed to create ESS cloud %s: %s", r.Version, err)
		return nil, fmt.Errorf("failed to create ESS cloud for version %s: %w", r.Version, err)
	}
	p.logger.Logf("Created cloud stack %s [stack_id: %s, deployment_id: %s]", r.Version, r.ID, resp.ID)
	return resp, nil
}

func (p *provisioner) getDeploymentID(stack runner.Stack) (string, error) {
	if stack.Internal == nil {
		return "", fmt.Errorf("missing internal information")
	}
	deploymentIDRaw, ok := stack.Internal["deployment_id"]
	if !ok {
		return "", fmt.Errorf("missing internal deployment_id")
	}
	deploymentID, ok := deploymentIDRaw.(string)
	if !ok {
		return "", fmt.Errorf("internal deployment_id not a string")
	}
	return deploymentID, nil
}

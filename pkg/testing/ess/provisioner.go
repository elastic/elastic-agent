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

	"golang.org/x/sync/errgroup"

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

func (p *provisioner) Provision(ctx context.Context, requests []runner.StackRequest) ([]runner.Stack, error) {
	results := make(map[runner.StackRequest]*CreateDeploymentResponse)
	for _, r := range requests {
		// allow up to 2 minutes for each create request
		createCtx, createCancel := context.WithTimeout(ctx, 2*time.Minute)
		resp, err := p.createDeployment(createCtx, r)
		createCancel()
		if err != nil {
			return nil, err
		}
		results[r] = resp
	}

	// wait 15 minutes for all stacks to be ready
	readyCtx, readyCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer readyCancel()

	g, gCtx := errgroup.WithContext(readyCtx)
	for req, resp := range results {
		g.Go(func(req runner.StackRequest, resp *CreateDeploymentResponse) func() error {
			return func() error {
				ready, err := p.client.DeploymentIsReady(gCtx, resp.ID, 30*time.Second)
				if err != nil {
					return fmt.Errorf("failed to check for cloud %s to be ready: %w", req.Version, err)
				}
				if !ready {
					return fmt.Errorf("cloud %s never became ready: %w", req.Version, err)
				}
				return nil
			}
		}(req, resp))
	}
	err := g.Wait()
	if err != nil {
		return nil, err
	}

	var stacks []runner.Stack
	for req, resp := range results {
		stacks = append(stacks, runner.Stack{
			ID:            req.ID,
			Version:       req.Version,
			Elasticsearch: resp.ElasticsearchEndpoint,
			Kibana:        resp.KibanaEndpoint,
			Username:      resp.Username,
			Password:      resp.Password,
			Internal: map[string]interface{}{
				"deployment_id": resp.ID,
			},
		})
	}
	return stacks, nil
}

// Clean cleans up all provisioned resources.
func (p *provisioner) Clean(ctx context.Context, stacks []runner.Stack) error {
	var errs []error
	for _, s := range stacks {
		err := p.destroyDeployment(ctx, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to destroy stack %s (%s): %w", s.Version, s.ID, err))
		}
	}
	if len(errs) > 0 {
		// go 1.19 doesn't have errors.Join, for now we just return the first error
		return errs[0]
	}
	return nil
}

func (p *provisioner) createDeployment(ctx context.Context, r runner.StackRequest) (*CreateDeploymentResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	p.logger.Logf("Creating stack %s (%s)", r.Version, r.ID)
	name := fmt.Sprintf("%s-%s", strings.Replace(p.cfg.Identifier, ".", "-", -1), r.ID)
	resp, err := p.client.CreateDeployment(ctx, CreateDeploymentRequest{
		Name:    name,
		Region:  p.cfg.Region,
		Version: r.Version,
	})
	if err != nil {
		p.logger.Logf("Failed to create ESS cloud %s: %s", r.Version, err)
		return nil, fmt.Errorf("failed to create ESS cloud for version %s: %w", r.Version, err)
	}
	return resp, nil
}

func (p *provisioner) destroyDeployment(ctx context.Context, s runner.Stack) error {
	if s.Internal == nil {
		return fmt.Errorf("missing internal information")
	}
	deploymentIDRaw, ok := s.Internal["deployment_id"]
	if !ok {
		return fmt.Errorf("missing internal deployment_id")
	}
	deploymentID, ok := deploymentIDRaw.(string)
	if !ok {
		return fmt.Errorf("internal deployment_id not a string")
	}

	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	p.logger.Logf("Destroying stack %s (%s)", s.Version, s.ID)
	return p.client.ShutdownDeployment(ctx, deploymentID)
}

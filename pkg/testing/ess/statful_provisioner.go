// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/version"
)

const ProvisionerStateful = "stateful"

// ProvisionerConfig is the configuration for the ESS StatefulProvisioner.
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

type StatefulProvisioner struct {
	logger common.Logger
	cfg    ProvisionerConfig
	client *Client
}

// NewProvisioner creates the ESS stateful Provisioner
func NewProvisioner(cfg ProvisionerConfig) (common.StackProvisioner, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	essClient := NewClient(Config{
		ApiKey: cfg.APIKey,
	})
	return &StatefulProvisioner{
		cfg:    cfg,
		client: essClient,
	}, nil
}

func (p *StatefulProvisioner) Name() string {
	return ProvisionerStateful
}

func (p *StatefulProvisioner) SetLogger(l common.Logger) {
	p.logger = l
	p.client.SetLogger(l)
}

// Create creates a stack.
func (p *StatefulProvisioner) Create(ctx context.Context, request common.StackRequest) (common.Stack, error) {
	// allow up to 2 minutes for request
	createCtx, createCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer createCancel()
	deploymentTags := map[string]string{
		"division":          "engineering",
		"org":               "ingest",
		"team":              "elastic-agent-control-plane",
		"project":           "elastic-agent",
		"integration-tests": "true",
	}
	// If the CI env var is set, this mean we are running inside the CI pipeline and some expected env vars are exposed
	if _, e := os.LookupEnv("CI"); e {
		deploymentTags["buildkite_id"] = os.Getenv("BUILDKITE_BUILD_NUMBER")
		deploymentTags["creator"] = os.Getenv("BUILDKITE_BUILD_CREATOR")
		deploymentTags["buildkite_url"] = os.Getenv("BUILDKITE_BUILD_URL")
		deploymentTags["ci"] = "true"
	}
	resp, err := p.createDeployment(createCtx, request, deploymentTags)
	if err != nil {
		return common.Stack{}, err
	}
	return common.Stack{
		ID:                 request.ID,
		Provisioner:        p.Name(),
		Version:            request.Version,
		Elasticsearch:      resp.ElasticsearchEndpoint,
		Kibana:             resp.KibanaEndpoint,
		IntegrationsServer: resp.IntegrationsServerEndpoint,
		Username:           resp.Username,
		Password:           resp.Password,
		Internal: map[string]interface{}{
			"deployment_id": resp.ID,
		},
		Ready: false,
	}, nil
}

// WaitForReady should block until the stack is ready and healthy or the context is cancelled.
func (p *StatefulProvisioner) WaitForReady(ctx context.Context, stack common.Stack) (common.Stack, error) {
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
func (p *StatefulProvisioner) Delete(ctx context.Context, stack common.Stack) error {
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

// Upgrade upgrades a stack to a new version.
func (p *StatefulProvisioner) Upgrade(ctx context.Context, stack common.Stack, newVersion string) error {
	deploymentID, err := p.getDeploymentID(stack)
	if err != nil {
		return fmt.Errorf("failed to get deployment ID from the stack: %w", err)
	}

	p.logger.Logf("Upgrading cloud stack %s [stack_id: %s, deployment_id: %s] to version %s", stack.Version, stack.ID, deploymentID, newVersion)

	// allow up to 10 minutes for request
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	err = p.client.UpgradeDeployment(ctx, deploymentID, newVersion)
	if err != nil {
		return fmt.Errorf("failed to upgrade cloud stack %s [stack_id: %s, deployment_id: %s] to version %s: %w", stack.Version, stack.ID, deploymentID, newVersion, err)
	}

	return nil
}

// AvailableVersions returns the stack versions available in the ECH region.
func (p *StatefulProvisioner) AvailableVersions() ([]*version.ParsedSemVer, error) {
	versionsApiUrl, err := url.JoinPath("regions", p.cfg.Region, "stack", "versions")
	if err != nil {
		return nil, fmt.Errorf("failed to create ECH versions API URL: %w", err)
	}
	versionsApiUrl += "?show_deleted=false&show_unusable=false"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p.logger.Logf("Getting available stack versions from ECH from %s", versionsApiUrl)
	resp, err := p.client.doGet(ctx, versionsApiUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to get versions from ECH for region [%s]: %w", p.cfg.Region, err)
	}
	defer resp.Body.Close()

	var stacks struct {
		Stacks []struct {
			Version string `json:"version"`
		} `json:"stacks"`
	}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&stacks)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECH versions API response from region [%s]: %w", p.cfg.Region, err)
	}

	var versions []*version.ParsedSemVer
	for _, stack := range stacks.Stacks {
		ver, err := version.ParseVersion(stack.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to parse stack version [%s]: %w", stack.Version, err)
		}
		versions = append(versions, ver)
	}

	return versions, nil
}

func (p *StatefulProvisioner) createDeployment(ctx context.Context, r common.StackRequest, tags map[string]string) (*CreateDeploymentResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	p.logger.Logf("Creating cloud stack %s [stack_id: %s]", r.Version, r.ID)
	name := fmt.Sprintf("%s-%s", strings.ReplaceAll(p.cfg.Identifier, ".", "-"), r.ID)

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

func (p *StatefulProvisioner) getDeploymentID(stack common.Stack) (string, error) {
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

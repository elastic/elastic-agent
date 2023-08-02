package ess

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

// ServerlessProvision contains
type ServerlessProvision struct {
	stacks map[string]stackhandlerData
	cfg    ProvisionerConfig
}

type stackhandlerData struct {
	client    *ServerlessClient
	stackData runner.Stack
}

// NewServerlessProvisioner creates a new StackProvisioner instance for serverless
func NewServerlessProvisioner(cfg ProvisionerConfig) ServerlessProvision {
	return ServerlessProvision{
		cfg:    cfg,
		stacks: map[string]stackhandlerData{},
	}
}

// Provision a new set of serverless instances
func (prov *ServerlessProvision) Provision(ctx context.Context, requests []runner.StackRequest) ([]runner.Stack, error) {
	for _, req := range requests {
		client := NewServerlessClient(prov.cfg.Region, "observability", prov.cfg.APIKey)
		req := ServerlessRequest{Name: req.ID, RegionID: prov.cfg.Region}
		response, err := client.DeployStack(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("error deploying stack for request %s: %w", req.ID, err)
		}
	}
}

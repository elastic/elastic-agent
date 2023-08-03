package ess

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

// ServerlessProvision contains
type ServerlessProvision struct {
	stacksMut sync.RWMutex
	stacks    map[string]stackhandlerData
	cfg       ProvisionerConfig
	log       runner.Logger
}

type defaultLogger struct {
	wrapped *logp.Logger
}

// / implements the runner.Logger interface
func (log *defaultLogger) Logf(format string, args ...any) {
	if len(args) == 0 {

	} else {
		log.wrapped.Infof(format, args)
	}

}

// tracks the data that maps to a single serverless deployment
type stackhandlerData struct {
	client    *ServerlessClient
	stackData runner.Stack
}

// ServerlessRegions is the JSON response from the serverless regions API endpoint
type ServerlessRegions struct {
	CSP       string `json:"csp"`
	CSPRegion string `json:"csp_region"`
	ID        string `json:"id"`
	Name      string `json:"name"`
}

// NewServerlessProvisioner creates a new StackProvisioner instance for serverless
func NewServerlessProvisioner(cfg ProvisionerConfig) (runner.StackProvisioner, error) {
	prov := &ServerlessProvision{
		cfg:    cfg,
		stacks: map[string]stackhandlerData{},
		log:    &defaultLogger{wrapped: logp.L()},
	}
	err := prov.CheckCloudRegion()
	if err != nil {
		return nil, fmt.Errorf("error checking region setting: %w", err)
	}
	return prov, nil
}

// SetLogger sets the logger for the
func (srv *ServerlessProvision) SetLogger(l runner.Logger) {
	srv.log = l
}

// Provision a new set of serverless instances
func (prov *ServerlessProvision) Provision(ctx context.Context, requests []runner.StackRequest) ([]runner.Stack, error) {

	upWaiter := sync.WaitGroup{}
	depErrs := make(chan error, len(requests))
	depUp := make(chan bool, len(requests))
	stacks := []runner.Stack{}
	for _, req := range requests {
		client := NewServerlessClient(prov.cfg.Region, "observability", prov.cfg.APIKey, prov.log)
		srvReq := ServerlessRequest{Name: req.ID, RegionID: prov.cfg.Region}
		_, err := client.DeployStack(ctx, srvReq)
		if err != nil {
			return nil, fmt.Errorf("error deploying stack for request %s: %w", req.ID, err)
		}
		err = client.WaitForEndpoints(ctx)
		if err != nil {
			return nil, fmt.Errorf("error waiting for endpoints to become available for request: %w", err)
		}
		newStack := runner.Stack{
			ID:            req.ID,
			Version:       req.Version,
			Elasticsearch: client.proj.Endpoints.Elasticsearch,
			Kibana:        client.proj.Endpoints.Kibana,
			Username:      client.proj.Credentials.Username,
			Password:      client.proj.Credentials.Password,
		}
		stacks = append(stacks, newStack)
		prov.stacksMut.Lock()
		prov.stacks[req.ID] = stackhandlerData{client: client, stackData: newStack}
		prov.stacksMut.Unlock()

		go func() {
			upWaiter.Add(1)
			isUp, err := client.DeploymentIsReady(ctx)
			if err != nil {
				depErrs <- err

			}
			depUp <- isUp
		}()
	}

	gotUp := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-depErrs:
			return nil, fmt.Errorf("error waiting for stacks to become available: %w", err)
		case isUp := <-depUp:
			if isUp {
				gotUp++
			}
			if gotUp >= len(requests) {
				return stacks, nil
			}
		}
	}

}

func (prov *ServerlessProvision) Clean(ctx context.Context, stacks []runner.Stack) error {

	for _, stack := range stacks {
		prov.stacksMut.RLock()
		stackRef, ok := prov.stacks[stack.ID]
		prov.stacksMut.RUnlock()
		if ok {
			err := stackRef.client.DeleteDeployment()
			if err != nil {
				prov.log.Logf("error removing deployment: %w", err)
			}
		} else {
			prov.log.Logf("error: could not find deployment for ID %s", stack.ID)
		}
	}
	return nil
}

// CheckCloudRegion checks to see if the provided region is valid for the serverless
// if we have an invalid region, overwrite with a valid one.
// The "normal" and serverless ESS APIs have different regions, hence why we need this.
func (prov *ServerlessProvision) CheckCloudRegion() error {
	urlPath := fmt.Sprintf("%s/api/v1/serverless/regions", serverlessURL)

	httpHandler, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		return fmt.Errorf("error creating new httpRequest: %w", err)
	}

	httpHandler.Header.Set("Content-Type", "application/json")
	httpHandler.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", prov.cfg.APIKey))

	resp, err := http.DefaultClient.Do(httpHandler)
	if err != nil {
		return fmt.Errorf("error performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Non-201 status code returned by server: %d, body: %s", resp.StatusCode, string(p))
	}
	regions := []ServerlessRegions{}

	err = json.NewDecoder(resp.Body).Decode(&regions)
	if err != nil {
		return fmt.Errorf("error unpacking regions from list: %w", err)
	}
	resp.Body.Close()

	found := false
	for _, region := range regions {
		if region.ID == prov.cfg.Region {
			found = true
		}
	}
	if !found {
		if len(regions) == 0 {
			return fmt.Errorf("No regions found for cloudless API")
		}
		newRegion := regions[0].ID
		prov.log.Logf("WARNING: Region %s is not available for serverless, selecting %s. Other regions are:", prov.cfg.Region, newRegion)
		for _, avail := range regions {
			prov.log.Logf(" %s - %s", avail.ID, avail.Name)
		}
		prov.cfg.Region = newRegion
	}

	return nil
}

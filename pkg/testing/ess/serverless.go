// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

var serverlessURL = "https://cloud.elastic.co"

// ServerlessClient is the handler the serverless ES instance
type ServerlessClient struct {
	region      string
	projectType string
	api         string
	proj        Project
	log         runner.Logger
}

// ServerlessRequest contains the data needed for a new serverless instance
type ServerlessRequest struct {
	Name     string `json:"name"`
	RegionID string `json:"region_id"`
}

// Project represents a serverless project
type Project struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Type   string `json:"type"`
	Region string `json:"region_id"`

	Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"credentials"`

	Endpoints struct {
		Elasticsearch string `json:"elasticsearch"`
		Kibana        string `json:"kibana"`
		Fleet         string `json:"fleet,omitempty"`
		APM           string `json:"apm,omitempty"`
	} `json:"endpoints"`
}

// NewServerlessClient creates a new instance of the serverless client
func NewServerlessClient(region, projectType, api string, logger runner.Logger) *ServerlessClient {
	return &ServerlessClient{
		region:      region,
		api:         api,
		projectType: projectType,
		log:         logger,
	}
}

// DeployStack creates a new serverless elastic stack
func (srv *ServerlessClient) DeployStack(ctx context.Context, req ServerlessRequest) (Project, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return Project{}, fmt.Errorf("error marshaling JSON request %w", err)
	}
	urlPath := fmt.Sprintf("%s/api/v1/serverless/projects/%s", serverlessURL, srv.projectType)

	httpHandler, err := http.NewRequestWithContext(ctx, "POST", urlPath, bytes.NewReader(reqBody))
	if err != nil {
		return Project{}, fmt.Errorf("error creating new httpRequest: %w", err)
	}

	httpHandler.Header.Set("Content-Type", "application/json")
	httpHandler.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", srv.api))

	resp, err := http.DefaultClient.Do(httpHandler)
	if err != nil {
		return Project{}, fmt.Errorf("error performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		p, _ := io.ReadAll(resp.Body)
		return Project{}, fmt.Errorf("Non-201 status code returned by server: %d, body: %s", resp.StatusCode, string(p))
	}

	serverlessHandle := Project{}
	err = json.NewDecoder(resp.Body).Decode(&serverlessHandle)
	if err != nil {
		return Project{}, fmt.Errorf("error decoding JSON response: %w", err)
	}
	srv.proj = serverlessHandle
	return serverlessHandle, nil
}

// DeploymentIsReady returns true when the serverless deployment is healthy and ready
func (srv *ServerlessClient) DeploymentIsReady(ctx context.Context) (bool, error) {
	err := srv.WaitForEndpoints(ctx)
	if err != nil {
		return false, fmt.Errorf("error waiting for endpoints to become available: %w", err)
	}
	srv.log.Logf("Endpoints available: ES: %s Fleet: %s Kibana: %s", srv.proj.Endpoints.Elasticsearch, srv.proj.Endpoints.Fleet, srv.proj.Endpoints.Kibana)
	err = srv.WaitForElasticsearch(ctx)
	if err != nil {
		return false, fmt.Errorf("error waiting for ES to become available: %w", err)
	}
	srv.log.Logf("Elasticsearch healthy...")
	err = srv.WaitForKibana(ctx)
	if err != nil {
		return false, fmt.Errorf("error waiting for Kibana to become available: %w", err)
	}
	srv.log.Logf("Kibana healthy...")

	return true, nil
}

// DeleteDeployment deletes the deployment
func (srv *ServerlessClient) DeleteDeployment() error {
	endpoint := fmt.Sprintf("%s/api/v1/serverless/projects/%s/%s", serverlessURL, srv.proj.Type, srv.proj.ID)
	req, err := http.NewRequestWithContext(context.Background(), "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", srv.api))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error performing delete request: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d from %s: %s", resp.StatusCode, req.URL, errBody)
	}
	return nil
}

// WaitForEndpoints polls the API and waits until fleet/ES endpoints are available
func (srv *ServerlessClient) WaitForEndpoints(ctx context.Context) error {
	reqURL := fmt.Sprintf("%s/api/v1/serverless/projects/%s/%s", serverlessURL, srv.proj.Type, srv.proj.ID)
	httpHandler, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error creating http request: %w", err)
	}

	httpHandler.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", srv.api))

	readyFunc := func(resp *http.Response) bool {
		project := &Project{}
		err = json.NewDecoder(resp.Body).Decode(project)
		resp.Body.Close()
		if err != nil {
			srv.log.Logf("response decoding error: %v", err)
			return false
		}
		if project.Endpoints.Elasticsearch != "" {
			// fake out the fleet URL, set to ES url
			if project.Endpoints.Fleet == "" {
				project.Endpoints.Fleet = strings.Replace(project.Endpoints.Elasticsearch, "es.eks", "fleet.eks", 1)
			}

			srv.proj.Endpoints = project.Endpoints
			return true
		}
		return false
	}

	err = srv.waitForRemoteState(ctx, httpHandler, time.Second*5, readyFunc)
	if err != nil {
		return fmt.Errorf("error waiting for remote instance to start: %w", err)
	}

	return nil
}

// WaitForElasticsearch waits until the ES endpoint is healthy
func (srv *ServerlessClient) WaitForElasticsearch(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/_cluster/health", srv.proj.Endpoints.Elasticsearch)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.SetBasicAuth(srv.proj.Credentials.Username, srv.proj.Credentials.Password)

	readyFunc := func(resp *http.Response) bool {
		var health struct {
			Status string `json:"status"`
		}
		err = json.NewDecoder(resp.Body).Decode(&health)
		resp.Body.Close()
		if err != nil {
			srv.log.Logf("response decoding error: %v", err)
			return false
		}
		if health.Status == "green" {
			return true
		}
		return false
	}

	err = srv.waitForRemoteState(ctx, req, time.Second*5, readyFunc)
	if err != nil {
		return fmt.Errorf("error waiting for ES to become healthy: %w", err)
	}
	return nil
}

// WaitForKibana waits until the kibana endpoint is healthy
func (srv *ServerlessClient) WaitForKibana(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", srv.proj.Endpoints.Kibana+"/api/status", nil)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.SetBasicAuth(srv.proj.Credentials.Username, srv.proj.Credentials.Password)

	readyFunc := func(resp *http.Response) bool {
		var status struct {
			Status struct {
				Overall struct {
					Level string `json:"level"`
				} `json:"overall"`
			} `json:"status"`
		}
		err = json.NewDecoder(resp.Body).Decode(&status)
		if err != nil {
			srv.log.Logf("response decoding error: %v", err)
			return false
		}
		resp.Body.Close()
		return status.Status.Overall.Level == "available"
	}

	err = srv.waitForRemoteState(ctx, req, time.Second*5, readyFunc)
	if err != nil {
		return fmt.Errorf("error waiting for ES to become healthy: %w", err)
	}
	return nil
}

func (srv *ServerlessClient) waitForRemoteState(ctx context.Context, httpHandler *http.Request, tick time.Duration, isReady func(*http.Response) bool) error {
	timer := time.NewTimer(time.Millisecond)
	// in cases where we get a timeout, also return the last error returned via HTTP
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("got context done; Last HTTP Error: %w", lastErr)
		case <-timer.C:
		}

		resp, err := http.DefaultClient.Do(httpHandler)
		if err != nil {
			errMsg := fmt.Errorf("request error: %w", err)
			// Logger interface doesn't have a debug level and we don't want to auto-log these;
			// as most of the time it's just spam.
			//srv.log.Logf(errMsg.Error())
			lastErr = errMsg
			timer.Reset(time.Second * 5)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			errBody, _ := io.ReadAll(resp.Body)
			errMsg := fmt.Errorf("unexpected status code %d in request to %s, body: %s", resp.StatusCode, httpHandler.URL.String(), string(errBody))
			//srv.log.Logf(errMsg.Error())
			lastErr = errMsg
			resp.Body.Close()
			timer.Reset(time.Second * 5)
			continue
		}

		if isReady(resp) {
			return nil
		}
		timer.Reset(tick)
	}
}

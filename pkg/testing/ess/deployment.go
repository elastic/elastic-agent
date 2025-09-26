// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v2"
)

type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CreateDeploymentRequest struct {
	Name    string `json:"name"`
	Region  string `json:"region"`
	Version string `json:"version"`
	Tags    []Tag  `json:"tags"`
}

type CreateDeploymentResponse struct {
	ID string `json:"id"`

	ElasticsearchEndpoint      string
	KibanaEndpoint             string
	IntegrationsServerEndpoint string

	Username string
	Password string
}

type GetDeploymentResponse struct {
	Elasticsearch struct {
		Status     DeploymentStatus
		ServiceUrl string
	}
	Kibana struct {
		Status     DeploymentStatus
		ServiceUrl string
	}
	IntegrationsServer struct {
		Status     DeploymentStatus
		ServiceUrl string
	}
}

type DeploymentStatus struct {
	Status  string
	Healthy bool
}

const (
	DeploymentStatusInitializing  = "initializing"
	DeploymentStatusReconfiguring = "reconfiguring"
	DeploymentStatusStarted       = "started"
)

type DeploymentStatusResponse struct {
	Overall DeploymentStatus

	Elasticsearch      DeploymentStatus
	Kibana             DeploymentStatus
	IntegrationsServer DeploymentStatus
}

// CreateDeployment creates the deployment with the specified configuration.
func (c *Client) CreateDeployment(ctx context.Context, req CreateDeploymentRequest) (*CreateDeploymentResponse, error) {
	reqBodyBytes, err := generateCreateDeploymentRequestBody(req)
	if err != nil {
		return nil, err
	}

	createResp, err := c.doPost(
		ctx,
		"deployments",
		"application/json",
		bytes.NewReader(reqBodyBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment creation API: %w", err)
	}
	defer createResp.Body.Close()

	var createRespBody struct {
		ID        string `json:"id"`
		Resources []struct {
			Kind        string `json:"kind"`
			Credentials struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"credentials"`
		} `json:"resources"`
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(createResp.Body).Decode(&createRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment creation API response: %w", err)
	}

	if len(createRespBody.Errors) > 0 {
		return nil, fmt.Errorf("failed to create: (%s) %s", createRespBody.Errors[0].Code, createRespBody.Errors[0].Message)
	}

	r := CreateDeploymentResponse{
		ID: createRespBody.ID,
	}

	for _, resource := range createRespBody.Resources {
		if resource.Kind == "elasticsearch" {
			r.Username = resource.Credentials.Username
			r.Password = resource.Credentials.Password
			break
		}
	}

	// Get Elasticsearch and Kibana endpoint URLs
	getResp, err := c.getDeployment(ctx, r.ID)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment retrieval API: %w", err)
	}
	defer getResp.Body.Close()

	var getRespBody struct {
		Resources struct {
			Elasticsearch []struct {
				Info struct {
					Metadata struct {
						ServiceUrl string `json:"service_url"`
					} `json:"metadata"`
				} `json:"info"`
			} `json:"elasticsearch"`
			Kibana []struct {
				Info struct {
					Metadata struct {
						ServiceUrl string `json:"service_url"`
					} `json:"metadata"`
				} `json:"info"`
			} `json:"kibana"`
			IntegrationsServer []struct {
				Info struct {
					Metadata struct {
						ServiceUrl string `json:"service_url"`
					} `json:"metadata"`
				} `json:"info"`
			} `json:"integrations_server"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(getResp.Body).Decode(&getRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment retrieval API response: %w", err)
	}

	r.ElasticsearchEndpoint = getRespBody.Resources.Elasticsearch[0].Info.Metadata.ServiceUrl
	r.KibanaEndpoint = getRespBody.Resources.Kibana[0].Info.Metadata.ServiceUrl
	r.IntegrationsServerEndpoint = getRespBody.Resources.IntegrationsServer[0].Info.Metadata.ServiceUrl

	return &r, nil
}

//go:embed upgrade_deployment_request.tmpl.json
var upgradeDeploymentRequestTemplate string

// UpgradeDeployment upgrades the specified deployment to the specified version.
func (c *Client) UpgradeDeployment(ctx context.Context, deploymentID string, version string) error {
	u, err := url.JoinPath("deployments", deploymentID)
	if err != nil {
		return fmt.Errorf("unable to create deployment update API URL: %w", err)
	}

	// Get deployment
	resp, err := c.doGet(ctx, u)
	if err != nil {
		return fmt.Errorf("unable to GET deployment: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read body of GET deployment API response: %w", err)
	}

	// Parse out values from body that will be needed in the upgrade request body
	var bodyObj struct {
		Resources struct {
			Elasticsearch []struct {
				Region string
			} `json:"elasticsearch"`
		} `json:"resources"`
	}
	err = json.Unmarshal(data, &bodyObj)
	if err != nil {
		return fmt.Errorf("unable to parse current deployment version from GET deployment API response: %w", err)
	}

	region := bodyObj.Resources.Elasticsearch[0].Region
	reqBodyBytes, err := generateUpgradeDeploymentRequestBody(region, version)
	if err != nil {
		return fmt.Errorf("unable to generate upgrade request body: %w", err)
	}

	upgradeResp, err := c.doPut(
		ctx,
		u,
		"application/json",
		bytes.NewReader(reqBodyBytes),
	)
	if err != nil {
		return fmt.Errorf("error calling deployment update API: %w", err)
	}
	defer upgradeResp.Body.Close()

	if upgradeResp.StatusCode != http.StatusOK {
		resBytes, _ := io.ReadAll(upgradeResp.Body)
		c.logger.Logf("Response body: %s", string(resBytes))
		return fmt.Errorf("got unexpected response code [%d] from deployment update API", upgradeResp.StatusCode)
	}

	var upgradeRespBody struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err = json.NewDecoder(upgradeResp.Body).Decode(&upgradeRespBody); err != nil {
		return fmt.Errorf("error parsing deployment update API response: %w", err)
	}

	if len(upgradeRespBody.Errors) > 0 {
		return fmt.Errorf("failed to upgrade: (%s) %s", upgradeRespBody.Errors[0].Code, upgradeRespBody.Errors[0].Message)
	}

	return nil
}

// ShutdownDeployment attempts to shut down the ESS deployment with the specified ID.
func (c *Client) ShutdownDeployment(ctx context.Context, deploymentID string) error {
	u, err := url.JoinPath("deployments", deploymentID, "_shutdown")
	if err != nil {
		return fmt.Errorf("unable to create deployment shutdown API URL: %w", err)
	}

	res, err := c.doPost(ctx, u, "", nil)
	if err != nil {
		return fmt.Errorf("error calling deployment shutdown API: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		resBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("got unexpected response code [%d] from deployment shutdown API: %s", res.StatusCode, string(resBytes))
	}

	return nil
}

// DeploymentStatus returns the overall status of the deployment as well as statuses of every component.
func (c *Client) DeploymentStatus(ctx context.Context, deploymentID string) (*DeploymentStatusResponse, error) {
	getResp, err := c.getDeployment(ctx, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment retrieval API: %w", err)
	}
	defer getResp.Body.Close()

	var getRespBody struct {
		Healthy   bool `json:"healthy"`
		Resources struct {
			Elasticsearch []struct {
				Info struct {
					Healthy bool   `json:"healthy"`
					Status  string `json:"status"`
				} `json:"info"`
			} `json:"elasticsearch"`
			Kibana []struct {
				Info struct {
					Healthy bool   `json:"healthy"`
					Status  string `json:"status"`
				} `json:"info"`
			} `json:"kibana"`
			IntegrationsServer []struct {
				Info struct {
					Healthy bool   `json:"healthy"`
					Status  string `json:"status"`
				} `json:"info"`
			} `json:"integrations_server"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(getResp.Body).Decode(&getRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment retrieval API response: %w", err)
	}

	s := DeploymentStatusResponse{
		Elasticsearch: DeploymentStatus{
			Status:  getRespBody.Resources.Elasticsearch[0].Info.Status,
			Healthy: getRespBody.Resources.Elasticsearch[0].Info.Healthy,
		},
		Kibana: DeploymentStatus{
			Status:  getRespBody.Resources.Kibana[0].Info.Status,
			Healthy: getRespBody.Resources.Kibana[0].Info.Healthy,
		},
		IntegrationsServer: DeploymentStatus{
			Status:  getRespBody.Resources.IntegrationsServer[0].Info.Status,
			Healthy: getRespBody.Resources.IntegrationsServer[0].Info.Healthy,
		},
	}
	s.Overall = DeploymentStatus{
		Status:  overallStatus(s.Elasticsearch.Status, s.Kibana.Status, s.IntegrationsServer.Status),
		Healthy: getRespBody.Healthy,
	}

	return &s, nil
}

// DeploymentIsReady returns true when the deployment is ready and healthy, checking its status
// every `tick` until `waitFor` duration.
func (c *Client) DeploymentIsReady(ctx context.Context, deploymentID string, tick time.Duration) (bool, error) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	var errs error
	statusCh := make(chan DeploymentStatus, 1)
	for {
		select {
		case <-ctx.Done():
			return false, errors.Join(errs, ctx.Err())
		case <-ticker.C:
			go func() {
				statusCtx, statusCancel := context.WithTimeout(ctx, tick)
				defer statusCancel()
				status, err := c.DeploymentStatus(statusCtx, deploymentID)
				if err != nil {
					errs = errors.Join(errs, err)
					return
				}
				statusCh <- status.Overall
			}()
		case status := <-statusCh:
			if status.Status == DeploymentStatusStarted && status.Healthy {
				return true, nil
			}
		}
	}
}

func (c *Client) getDeployment(ctx context.Context, deploymentID string) (*http.Response, error) {
	u, err := url.JoinPath("deployments", deploymentID)
	if err != nil {
		return nil, fmt.Errorf("unable to create deployment retrieval API URL: %w", err)
	}

	return c.doGet(ctx, u)
}

func overallStatus(statuses ...string) string {
	// The overall status is started if every component's status is started. Otherwise,
	// we take the non-started components' statuses and pick the first one as the overall
	// status.
	statusMap := map[string]struct{}{}
	for _, status := range statuses {
		statusMap[status] = struct{}{}
	}

	if len(statusMap) == 1 {
		if _, allStarted := statusMap[DeploymentStatusStarted]; allStarted {
			return DeploymentStatusStarted
		}
	}

	var overallStatus string
	for _, status := range statuses {
		if status != DeploymentStatusStarted {
			overallStatus = status
			break
		}
	}

	return overallStatus
}

//go:embed create_deployment_request.tmpl.json
var createDeploymentRequestTemplate string

//go:embed create_deployment_csp_configuration.yaml
var cloudProviderSpecificValues []byte

func generateCreateDeploymentRequestBody(req CreateDeploymentRequest) ([]byte, error) {
	csp, err := parseCSPFromRegion(req.Region)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSP from region [%s]: %w", req.Region, err)
	}

	templateContext, err := createDeploymentTemplateContext(csp, req)
	if err != nil {
		return nil, fmt.Errorf("creating request template context: %w", err)
	}

	tpl, err := template.New("create_deployment_request").
		Funcs(template.FuncMap{"json": jsonMarshal}).
		Parse(createDeploymentRequestTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse deployment creation template: %w", err)
	}

	var bBuf bytes.Buffer
	err = tpl.Execute(&bBuf, templateContext)
	if err != nil {
		return nil, fmt.Errorf("rendering create deployment request template with context %v : %w", templateContext, err)
	}
	return bBuf.Bytes(), nil
}

func parseCSPFromRegion(region string) (string, error) {
	// Special case: AWS us-east-1 region is just called
	// us-east-1 (instead of aws-us-east-1)!
	if region == "us-east-1" {
		return "aws", nil
	}

	regionParts := strings.Split(region, "-")
	if len(regionParts) < 2 {
		return "", fmt.Errorf("unable to parse CSP out of region [%s]", region)
	}

	return regionParts[0], nil
}

func jsonMarshal(in any) (string, error) {
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func createDeploymentTemplateContext(csp string, req any) (map[string]any, error) {
	cspSpecificContext, err := loadCspValues(csp)
	if err != nil {
		return nil, fmt.Errorf("loading csp-specific values for %q: %w", csp, err)
	}

	cspSpecificContext["request"] = req

	return cspSpecificContext, nil
}

func loadCspValues(csp string) (map[string]any, error) {
	var cspValues map[string]map[string]any

	err := yaml.Unmarshal(cloudProviderSpecificValues, &cspValues)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling error: %w", err)
	}
	values, supportedCSP := cspValues[csp]
	if !supportedCSP {
		return nil, fmt.Errorf("csp %s not supported", csp)
	}

	// check for docker overrides
	if dockerValues, dockerValuesFound := cspValues["docker"]; dockerValuesFound {
		values["docker"] = dockerValues
	}

	return values, nil
}

func generateUpgradeDeploymentRequestBody(region, version string) ([]byte, error) {
	csp, err := parseCSPFromRegion(region)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSP from region [%s]: %w", region, err)
	}

	req := map[string]string{
		"region":  region,
		"version": version,
	}

	templateContext, err := createDeploymentTemplateContext(csp, req)
	if err != nil {
		return nil, fmt.Errorf("creating request template context: %w", err)
	}

	tpl, err := template.New("upgrade_deployment_request").
		Funcs(template.FuncMap{"json": jsonMarshal}).
		Parse(upgradeDeploymentRequestTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse deployment upgrade template: %w", err)
	}

	var bBuf bytes.Buffer
	err = tpl.Execute(&bBuf, templateContext)
	if err != nil {
		return nil, fmt.Errorf("rendering upgrade deployment request template with context %v: %w", templateContext, err)
	}
	return bBuf.Bytes(), nil
}

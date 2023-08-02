// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#createPackagePolicy
// request https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#package_policy_request
type PackagePolicyRequest struct {
	ID        string                      `json:"id,omitempty"`
	Name      string                      `json:"name"`
	Namespace string                      `json:"namespace"`
	PolicyID  string                      `json:"policy_id"`
	Package   PackagePolicyRequestPackage `json:"package"`
	Vars      map[string]interface{}      `json:"vars"`
	Inputs    []map[string]interface{}    `json:"inputs"`
	Force     bool                        `json:"force"`
}

type PackagePolicyRequestPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#create_package_policy_200_response
type PackagePolicyResponse struct {
	Item PackagePolicy `json:"item"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#package_policy
type PackagePolicy struct {
	ID          string                      `json:"id,omitempty"`
	Revision    int                         `json:"revision"`
	Enabled     bool                        `json:"enabled"`
	Inputs      []map[string]interface{}    `json:"inputs"`
	Package     PackagePolicyRequestPackage `json:"package"`
	Namespace   string                      `json:"namespace"`
	OutputID    string                      `json:"output_id"`
	PolicyID    string                      `json:"policy_id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#delete_package_policy_200_response
type DeletePackagePolicyResponse struct {
	ID string `json:"id"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#fleet_server_health_check_400_response
type FleetErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

const (
	fleetAgentPoliciesAPI   = "/api/fleet/agent_policies"
	fleetAgentPolicyAPI     = "/api/fleet/agent_policies/%s"
	fleetPackagePoliciesAPI = "/api/fleet/package_policies"
	fleetUninstallTokensAPI = "/api/fleet/uninstall_tokens" //nolint:gosec // NOT the "Potential hardcoded credentials"
)

// InstallFleetPackage uses the Fleet package policies API install an integration package as specified in the request.
// Note that the package policy ID and Name must be globally unique across all installed packages.
// TODO: Move this to https://github.com/elastic/elastic-agent-libs/blob/main/kibana/fleet.go
func InstallFleetPackage(ctx context.Context, kib *kibana.Client, req *PackagePolicyRequest) (r PackagePolicyResponse, err error) {
	reqBytes, err := json.Marshal(&req)
	if err != nil {
		return r, fmt.Errorf("marshalling request json: %w", err)
	}

	resp, err := kib.Connection.SendWithContext(ctx,
		http.MethodPost,
		fleetPackagePoliciesAPI,
		nil,
		nil,
		bytes.NewReader(reqBytes),
	)
	if err != nil {
		return r, fmt.Errorf("posting %s: %w", fleetPackagePoliciesAPI, err)
	}
	defer resp.Body.Close()

	err = readJSONResponse(resp, &r)
	return r, err
}

func DeleteFleetPackage(ctx context.Context, kib *kibana.Client, packagePolicyID string) (r DeletePackagePolicyResponse, err error) {
	url := fmt.Sprintf("%v/%v", fleetPackagePoliciesAPI, packagePolicyID)
	resp, err := kib.Connection.SendWithContext(ctx,
		http.MethodDelete,
		url,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return r, fmt.Errorf("DELETE %s: %w", url, err)
	}
	defer resp.Body.Close()

	err = readJSONResponse(resp, &r)
	return r, err
}

// UninstallTokenResponse uninstall tokens response with resolved token values
type UninstallTokenResponse struct {
	Items   []UninstallTokenItem `json:"items"`
	Total   int                  `json:"total"`
	Page    int                  `json:"page"`
	PerPage int                  `json:"perPage"`
}

type UninstallTokenItem struct {
	ID        string `json:"id"`
	PolicyID  string `json:"policy_id"`
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
}

type uninstallTokenValueResponse struct {
	Item UninstallTokenItem `json:"item"`
}

// GetPolicyUninstallTokens Retrieves the the policy uninstall tokens
func GetPolicyUninstallTokens(ctx context.Context, kib *kibana.Client, policyID string) (r UninstallTokenResponse, err error) {
	// Fetch uninstall token for the policy
	// /api/fleet/uninstall_tokens?policyId={policyId}&page=1&perPage=1000
	q := make(url.Values)
	q.Add("policyId", policyID)
	q.Add("page", "1")
	q.Add("perPage", "1000")

	resp, err := kib.Connection.SendWithContext(ctx,
		http.MethodGet,
		fleetUninstallTokensAPI,
		q,
		nil,
		nil,
	)
	if err != nil {
		return r, fmt.Errorf("getting %s: %w", fleetUninstallTokensAPI, err)
	}
	defer resp.Body.Close()

	err = readJSONResponse(resp, &r)
	if err != nil {
		return r, err
	}

	// Resolve token values for token ID
	for i := 0; i < len(r.Items); i++ {
		tokRes, err := GetUninstallToken(ctx, kib, r.Items[i].ID)
		if err != nil {
			return r, err
		}
		r.Items[i] = tokRes
	}

	return r, nil
}

// GetUninstallToken return uninstall token value for the given token ID
func GetUninstallToken(ctx context.Context, kib *kibana.Client, tokenID string) (r UninstallTokenItem, err error) {
	u, err := url.JoinPath(fleetUninstallTokensAPI, tokenID)
	if err != nil {
		return r, err
	}

	resp, err := kib.Connection.SendWithContext(ctx,
		http.MethodGet,
		u,
		nil,
		nil,
		nil,
	)

	if err != nil {
		return r, fmt.Errorf("getting %s: %w", u, err)
	}
	defer resp.Body.Close()

	var res uninstallTokenValueResponse
	err = readJSONResponse(resp, &res)
	return res.Item, err
}

// Temporary
// TODO: Remove after elastic-agent-libs PR is merged with updated wrapper
type ExpandedAgentPolicy struct {
	kibana.AgentPolicy
	IsProtected bool `json:"is_protected"`
}

// Temporary
// TODO: Remove after elastic-agent-libs PR is merged with updated wrapper
// Constant booleans for convenience for dealing with *bool
var (
	bt bool = true
	bf bool = false

	TRUE  *bool = &bt
	FALSE *bool = &bf
)

// Temporary
// TODO: Remove after elastic-agent-libs PR is merged with updated wrapper
type ExpandedAgentPolicyUpdateRequest struct {
	kibana.AgentPolicyUpdateRequest
	IsProtected bool `json:"is_protected"`
}

type policyResp struct {
	Item kibana.PolicyResponse `json:"item"`
}

// Temporary
// TODO: Remove after elastic-agent-libs PR is merged with updated wrapper
func CreatePolicy(ctx context.Context, kib *kibana.Client, request ExpandedAgentPolicy) (r kibana.PolicyResponse, err error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return r, fmt.Errorf("unable to marshal create policy request into JSON: %w", err)
	}

	resp, err := kib.Connection.SendWithContext(ctx, http.MethodPost, fleetAgentPoliciesAPI, nil, nil, bytes.NewReader(reqBody))
	if err != nil {
		return r, fmt.Errorf("error calling create policy API: %w", err)
	}
	defer resp.Body.Close()
	var updatePolicyResp policyResp
	err = readJSONResponse(resp, &updatePolicyResp)
	return updatePolicyResp.Item, err
}

// Temporary
// TODO: Remove after elastic-agent-libs PR is merged with updated wrapper
func UpdatePolicy(ctx context.Context, kib *kibana.Client, ID string, request ExpandedAgentPolicyUpdateRequest) (r kibana.PolicyResponse, err error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return r, fmt.Errorf("unable to marshal update policy request into JSON: %w", err)
	}

	apiURL := fmt.Sprintf(fleetAgentPolicyAPI, ID)

	resp, err := kib.Connection.SendWithContext(ctx, http.MethodPut, apiURL, nil, nil, bytes.NewReader(reqBody))

	if err != nil {
		return r, fmt.Errorf("error calling update policy API: %w", err)
	}
	defer resp.Body.Close()

	var updatePolicyResp policyResp
	err = readJSONResponse(resp, &updatePolicyResp)
	return updatePolicyResp.Item, err
}

// This is a subset of kibana.AgentPolicyUpdateRequest, using until elastic-agent-libs PR https://github.com/elastic/elastic-agent-libs/pull/141 is merged
// TODO: replace with the elastic-agent-libs when avaiable
type AgentPolicyUpdateRequest struct {
	// Name of the policy. Required in an update request.
	Name string `json:"name"`
	// Namespace of the policy. Required in an update request.
	Namespace   string `json:"namespace"`
	IsProtected bool   `json:"is_protected"`
}

func readJSONResponse(resp *http.Response, v any) error {
	if resp.StatusCode != http.StatusOK {
		return client.ExtractError(resp.Body)
	}

	err := json.NewDecoder(resp.Body).Decode(v)
	if err != nil {
		return fmt.Errorf("unmarshalling response json: %w", err)
	}

	return nil
}

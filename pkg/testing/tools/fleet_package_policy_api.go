package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/elastic/elastic-agent-libs/kibana"
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

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#fleet_server_health_check_400_response
type FleetErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

const PackagePoliciesAPI = "/api/fleet/package_policies"

// InstallFleetPackage uses the Fleet package policies API install an integration package as specified in the request.
// Note that the package policy ID and Name must be globally unique across all installed packages.
// TODO: Move this to https://github.com/elastic/elastic-agent-libs/blob/main/kibana/fleet.go
func InstallFleetPackage(ctx context.Context, kib *kibana.Client, req *PackagePolicyRequest) (*PackagePolicyResponse, error) {
	reqBytes, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("marshalling request json: %w", err)
	}

	resp, err := kib.Connection.SendWithContext(ctx,
		http.MethodPost,
		PackagePoliciesAPI,
		nil,
		nil,
		bytes.NewReader(reqBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("posting %s: %w", PackagePoliciesAPI, err)
	}
	defer resp.Body.Close()

	pkgRespBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		fleetErr := FleetErrorResponse{}
		err = json.Unmarshal(pkgRespBytes, &fleetErr)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling http error response with code %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("http error response with code %d: %+v", resp.StatusCode, fleetErr)
	}

	pkgPolicyResp := PackagePolicyResponse{}
	err = json.Unmarshal(pkgRespBytes, &pkgPolicyResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling response json: %w", err)
	}

	return &pkgPolicyResp, nil
}
